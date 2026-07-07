"""SAP GenAI Hub model provider.

- Docs: https://help.sap.com/docs/sap-ai-core/sap-ai-core-service-guide/consume-generative-ai-models-using-sap-ai-core#aws-bedrock
- SDK Reference: https://help.sap.com/doc/generative-ai-hub-sdk/CLOUD/en-US/_reference/gen_ai_hub.html
"""

import json
import logging
import os
from typing import (
    Any,
    AsyncGenerator,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Union,
    cast,
    TypeVar,
    Type,
    Callable,
)

from pydantic import BaseModel
from typing_extensions import TypedDict, Unpack, override

# Bound to Pydantic models — the schema types passed to structured_output.
T = TypeVar("T", bound=BaseModel)

from strands.types.content import ContentBlock, Messages
from strands.types.exceptions import (
    ContextWindowOverflowException,
    ModelThrottledException,
)
from strands.models import Model
from strands.types.streaming import StreamEvent
from strands.types.tools import ToolSpec

# Import SAP GenAI Hub SDK
try:
    from gen_ai_hub.proxy.native.amazon.clients import Session
except ImportError:
    raise ImportError(
        "SAP GenAI Hub SDK is not installed. Please install it with: "
        "pip install 'generative-ai-hub-sdk[all]'"
    )

logger = logging.getLogger(__name__)

DEFAULT_SAP_GENAI_HUB_MODEL_ID = "amazon--nova-lite"

# Common error messages for context window overflow
CONTEXT_WINDOW_OVERFLOW_MESSAGES = [
    "Input is too long for requested model",
    "input length and `max_tokens` exceed context limit",
    "too many total text bytes",
]


class SAPGenAIHubModel(Model):
    """SAP GenAI Hub model provider implementation.

    This implementation handles SAP GenAI Hub-specific features such as:
    - Tool configuration for function calling
    - Streaming responses
    - Context window overflow detection
    - Support for different model types (Nova, Claude, Titan)
    """

    class SAPGenAIHubConfig(TypedDict, total=False):
        """Configuration options for SAP GenAI Hub models.

        Attributes:
            additional_args: Any additional arguments to include in the request
            max_tokens: Maximum number of tokens to generate in the response
            model_id: The SAP GenAI Hub model ID (e.g., "amazon--nova-lite", "anthropic--claude-3-sonnet")
            stop_sequences: List of sequences that will stop generation when encountered
            streaming: Flag to enable/disable streaming. Defaults to True.
            temperature: Controls randomness in generation (higher = more random)
            top_p: Controls diversity via nucleus sampling (alternative to temperature)
        """

        additional_args: Optional[Dict[str, Any]]
        max_tokens: Optional[int]
        model_id: str
        stop_sequences: Optional[List[str]]
        streaming: Optional[bool]
        temperature: Optional[float]
        top_p: Optional[float]

    def __init__(
        self,
        **model_config: Unpack[SAPGenAIHubConfig],
    ):
        """Initialize provider instance.

        Args:
            **model_config: Configuration options for the SAP GenAI Hub model.
        """
        self.config = SAPGenAIHubModel.SAPGenAIHubConfig(
            model_id=DEFAULT_SAP_GENAI_HUB_MODEL_ID
        )
        self.update_config(**model_config)

        # logger.debug("config=<%s> | initializing", self.config)

        # Initialize the SAP GenAI Hub client not BOTO3
        self.client = Session().client(model_name=self.config["model_id"])

    @override
    def update_config(self, **model_config: Unpack[SAPGenAIHubConfig]) -> None:  # type: ignore
        """Update the SAP GenAI Hub Model configuration with the provided arguments.

        Args:
            **model_config: Configuration overrides.
        """
        self.config.update(model_config)

    @override
    def get_config(self) -> SAPGenAIHubConfig:
        """Get the current SAP GenAI Hub Model configuration.

        Returns:
            The SAP GenAI Hub model configuration.
        """
        return self.config

    def _is_nova_model(self) -> bool:
        """Check if the current model is an Amazon Nova model.

        Returns:
            True if the model is an Amazon Nova model, False otherwise.
        """
        nova_models = ["amazon--nova-pro", "amazon--nova-micro", "amazon--nova-lite"]
        return self.config["model_id"] in nova_models

    def _is_claude_model(self) -> bool:
        """Check if the current model is an Anthropic Claude model.

        Returns:
            True if the model is an Anthropic Claude model, False otherwise.
        """
        return self.config["model_id"].startswith("anthropic--claude")

    def _is_titan_embed_model(self) -> bool:
        """Check if the current model is an Amazon Titan Embedding model.

        Returns:
            True if the model is an Amazon Titan Embedding model, False otherwise.
        """
        return self.config["model_id"] == "amazon--titan-embed-text"

    @override
    def format_request(
        self,
        messages: Messages,
        tool_specs: Optional[List[ToolSpec]] = None,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Format a request for the SAP GenAI Hub model.
        Taken from documentation here: https://help.sap.com/docs/sap-ai-core/sap-ai-core-service-guide/consume-generative-ai-models-using-sap-ai-core#concept_ynz_mgh_tzb__section_kx4_qg4_mbc

        Args:
            messages: List of message objects to be processed by the model.
            tool_specs: List of tool specifications to make available to the model.
            system_prompt: System prompt to provide context to the model.

        Returns:
            A formatted request for the SAP GenAI Hub model.
        """
        # Format request based on model type
        if self._is_nova_model():
            return self._format_nova_request(messages, tool_specs, system_prompt)
        elif self._is_claude_model():
            return self._format_claude_request(messages, tool_specs, system_prompt)
        elif self._is_titan_embed_model():
            return self._format_titan_embed_request(messages)
        else:
            raise ValueError(f"Unsupported model: {self.config['model_id']}")

    def _format_nova_request(
        self,
        messages: Messages,
        tool_specs: Optional[List[ToolSpec]] = None,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Format a request for Amazon Nova models.

        Args:
            messages: List of message objects to be processed by the model.
            tool_specs: List of tool specifications to make available to the model.
            system_prompt: System prompt to provide context to the model.

        Returns:
            A formatted request for Amazon Nova models.
        """
        request = {
            "messages": messages,
            "inferenceConfig": {
                key: value
                for key, value in [
                    ("maxTokens", self.config.get("max_tokens")),
                    ("temperature", self.config.get("temperature")),
                    ("topP", self.config.get("top_p")),
                    ("stopSequences", self.config.get("stop_sequences")),
                ]
                if value is not None
            },
        }

        # Add system prompt if provided
        if system_prompt:
            request["system"] = [{"text": system_prompt}]

        # Add tool specs if provided
        if tool_specs:
            request["toolConfig"] = {
                "tools": [{"toolSpec": tool_spec} for tool_spec in tool_specs],
                "toolChoice": {"auto": {}},
            }

        # Add additional arguments if provided
        if (
            "additional_args" in self.config
            and self.config["additional_args"] is not None
        ):
            request.update(self.config["additional_args"])

        return request

    def _format_claude_request(
        self,
        messages: Messages,
        tool_specs: Optional[List[ToolSpec]] = None,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Format a request for Anthropic Claude models.

        Args:
            messages: List of message objects to be processed by the model.
            tool_specs: List of tool specifications to make available to the model.
            system_prompt: System prompt to provide context to the model.

        Returns:
            A formatted request for Anthropic Claude models.
        """
        # For Claude models, we'll use the same format as Nova models
        # since we're using the converse API for both
        request = {
            "messages": messages,
            "inferenceConfig": {
                key: value
                for key, value in [
                    ("maxTokens", self.config.get("max_tokens")),
                    ("temperature", self.config.get("temperature")),
                    ("topP", self.config.get("top_p")),
                    ("stopSequences", self.config.get("stop_sequences")),
                ]
                if value is not None
            },
        }

        # Add system prompt if provided
        if system_prompt:
            request["system"] = [{"text": system_prompt}]

        # Add tool specs if provided
        if tool_specs:
            request["toolConfig"] = {
                "tools": [{"toolSpec": tool_spec} for tool_spec in tool_specs],
                "toolChoice": {"auto": {}},
            }

        # Add additional arguments if provided
        if (
            "additional_args" in self.config
            and self.config["additional_args"] is not None
        ):
            request.update(self.config["additional_args"])

        return request

    def _format_titan_embed_request(self, messages: Messages) -> Dict[str, Any]:
        """Format a request for Amazon Titan Embedding models.

        Args:
            messages: List of message objects to be processed by the model.

        Returns:
            A formatted request for Amazon Titan Embedding models.
        """
        # Extract the text from the last user message
        input_text = ""
        for message in reversed(messages):
            if message["role"] == "user" and "content" in message:
                content_blocks = message["content"]
                if isinstance(content_blocks, list):
                    for block in content_blocks:
                        if "text" in block:
                            input_text = block["text"]
                            break
                if input_text:
                    break

        request = {
            "inputText": input_text,
        }

        # Add additional arguments if provided
        if (
            "additional_args" in self.config
            and self.config["additional_args"] is not None
        ):
            request.update(self.config["additional_args"])

        return request

    @override
    def format_chunk(self, event: Dict[str, Any]) -> StreamEvent:
        """Format the SAP GenAI Hub response events into standardized message chunks.

        Args:
            event: A response event from the SAP GenAI Hub model.

        Returns:
            The formatted chunk.
        """
        # Handle string events by wrapping them in a proper structure
        if isinstance(event, str):
            return {
                "contentBlockDelta": {
                    "delta": {"text": event}
                }
            }
        
        # If it's already a proper dictionary, return it as is
        if isinstance(event, dict):
            return cast(StreamEvent, event)
        
        # For any other type, convert to string and wrap
        return {
            "contentBlockDelta": {
                "delta": {"text": str(event)}
            }
        }

    def _convert_streaming_response(
        self, stream_response: Any
    ) -> Iterable[StreamEvent]:
        """Convert a streaming response to the standardized streaming format.

        Args:
            stream_response: The streaming response from the SAP GenAI Hub model.

        Returns:
            An iterable of response events in the streaming format.
        """
        try:
            # logger.debug(f"Converting streaming response of type: {type(stream_response)}")
            
            # SAP GenAI Hub streaming responses might be different formats
            # Let's handle the most common patterns
            
            message_started = False
            event_count = 0
            content_received = False
            
            # Check if it's a Bedrock-style response with 'stream' key
            if hasattr(stream_response, 'get') and callable(getattr(stream_response, 'get')):
                event_stream = stream_response.get('stream')
                if event_stream:
                    # logger.debug("Processing Bedrock-style event stream")
                    
                    for event in event_stream:
                        event_count += 1
                        # logger.debug(f"Processing stream event {event_count}: {event}")
                        
                        # Start message if not started
                        if not message_started:
                            yield {"messageStart": {"role": "assistant"}}
                            message_started = True
                        
                        # Process the event based on its structure
                        if isinstance(event, dict):
                            # Pass through properly formatted events
                            if any(key in event for key in ['contentBlockDelta', 'contentBlockStart', 'contentBlockStop', 'messageStart', 'messageStop', 'metadata']):
                                if 'contentBlockDelta' in event:
                                    content_received = True
                                yield event
                            else:
                                # Format unknown events
                                formatted_event = self.format_chunk(event)
                                if 'contentBlockDelta' in formatted_event:
                                    content_received = True
                                yield formatted_event
                        else:
                            # Handle non-dict events (strings, etc.)
                            formatted_event = self.format_chunk(event)
                            if 'contentBlockDelta' in formatted_event:
                                content_received = True
                            yield formatted_event
                    
                    # Don't add extra messageStop - it should come from the stream itself
                    # logger.debug(f"Processed {event_count} events from Bedrock stream, content_received: {content_received}")
                    return
            
            # Try to iterate directly over the stream_response
            try:
                # logger.debug("Attempting direct iteration over stream_response")
                # logger.debug(f"Stream response attributes: {dir(stream_response)}")
                
                # Check if this is a generator or iterator
                if hasattr(stream_response, '__iter__'):
                    logger.debug("Stream response is iterable")
                    
                    for event in stream_response:
                        event_count += 1
                        logger.debug(f"Processing direct stream event {event_count}: {type(event)} - {event}")
                        
                        # Start message if not started
                        if not message_started:
                            yield {"messageStart": {"role": "assistant"}}
                            message_started = True
                        
                        # Process the event
                        if isinstance(event, dict):
                            # Check if it's already a properly formatted streaming event
                            if any(key in event for key in ['contentBlockDelta', 'contentBlockStart', 'contentBlockStop', 'messageStart', 'messageStop', 'metadata']):
                                if 'contentBlockDelta' in event:
                                    content_received = True
                                
                                # Always yield the event as-is, including messageStop
                                yield event
                                
                                # If this is a messageStop event, we're done with this stream
                                if 'messageStop' in event:
                                    logger.debug(f"Received messageStop event from stream: {event}")
                                    return
                            else:
                                # Format unknown events
                                formatted_event = self.format_chunk(event)
                                if 'contentBlockDelta' in formatted_event:
                                    content_received = True
                                yield formatted_event
                        else:
                            # Handle strings and other types
                            formatted_event = self.format_chunk(event)
                            if 'contentBlockDelta' in formatted_event:
                                content_received = True
                            yield formatted_event
                    
                    # Don't add extra messageStop - it should come from the stream itself
                    logger.debug(f"Processed {event_count} events from direct iteration, content_received: {content_received}")
                else:
                    logger.debug("Stream response is not iterable, treating as single response")
                    yield {"messageStart": {"role": "assistant"}}
                    formatted_event = self.format_chunk(stream_response)
                    yield formatted_event
                    # Don't add messageStop for non-streaming responses
                
            except TypeError as te:
                # stream_response is not iterable
                logger.debug(f"Stream response not iterable ({te}), treating as single response")
                yield {"messageStart": {"role": "assistant"}}
                formatted_event = self.format_chunk(stream_response)
                yield formatted_event
                # Don't add messageStop for non-iterable responses
                
        except Exception as e:
            logger.error(f"Error processing streaming response: {e}")
            logger.error(f"Stream response type: {type(stream_response)}")
            logger.error(f"Stream response attributes: {dir(stream_response) if hasattr(stream_response, '__dict__') else 'No attributes'}")
            raise e

    async def _convert_non_streaming_to_streaming(
        self, response: Dict[str, Any]
    ) -> Iterable[StreamEvent]:
        """Convert a non-streaming response to the streaming format.

        Args:
            response: The non-streaming response from the SAP GenAI Hub model.

        Returns:
            An iterable of response events in the streaming format.
        """
        if self._is_nova_model() or self._is_claude_model():
            # Nova and Claude models have a similar response format when using converse API
            # Yield messageStart event
            yield {"messageStart": {"role": response["output"]["message"]["role"]}}

            # Process content blocks
            for content in response["output"]["message"]["content"]:
                # Yield contentBlockStart event if needed
                if "toolUse" in content:
                    yield {
                        "contentBlockStart": {
                            "start": {
                                "toolUse": {
                                    "toolUseId": content["toolUse"]["toolUseId"],
                                    "name": content["toolUse"]["name"],
                                }
                            },
                        }
                    }

                    # For tool use, we need to yield the input as a delta
                    input_value = json.dumps(content["toolUse"]["input"])

                    yield {
                        "contentBlockDelta": {
                            "delta": {"toolUse": {"input": input_value}}
                        }
                    }
                elif "text" in content:
                    # Then yield the text as a delta
                    yield {
                        "contentBlockDelta": {
                            "delta": {"text": content["text"]},
                        }
                    }

                # Yield contentBlockStop event
                yield {"contentBlockStop": {}}

            # Yield messageStop event
            yield {
                "messageStop": {
                    "stopReason": response.get("stopReason", "stop"),
                }
            }

            # Yield metadata event
            if "usage" in response or "metrics" in response:
                metadata: StreamEvent = {"metadata": {}}
                if "usage" in response:
                    metadata["metadata"]["usage"] = response["usage"]
                if "metrics" in response:
                    metadata["metadata"]["metrics"] = response["metrics"]
                yield metadata

        elif self._is_titan_embed_model():
            # Titan Embedding models have a different response format
            # Yield messageStart event
            yield {"messageStart": {"role": "assistant"}}

            # Yield content block for embedding
            if "embedding" in response:
                yield {
                    "contentBlockDelta": {
                        "delta": {
                            "text": f"Embedding generated with {len(response['embedding'])} dimensions"
                        },
                    }
                }

            # Yield contentBlockStop event
            yield {"contentBlockStop": {}}

            # Yield messageStop event
            yield {
                "messageStop": {
                    "stopReason": "stop",
                }
            }

    @override
    async def stream(
        self,
        messages: Messages,
        tool_specs: Optional[List[ToolSpec]] = None,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> Iterable[StreamEvent]:
        """Send the request to the SAP GenAI Hub model and get the response.

        Args:
            messages: List of message objects to be processed by the model.
            tool_specs: List of tool specifications to make available to the model.
            system_prompt: System prompt to provide context to the model.
            **kwargs: Additional keyword arguments.

        Returns:
            An iterable of response events from the SAP GenAI Hub model

        Raises:
            ContextWindowOverflowException: If the input exceeds the model's context window.
            ModelThrottledException: If the model service is throttling requests.
        """
        request = self.format_request(messages, tool_specs, system_prompt)
        streaming = self.config.get("streaming", True)

        try:
            if self._is_nova_model() or self._is_claude_model():
                if streaming:
                    # Use converse_stream for streaming responses
                    try:
                        logger.debug("Attempting to use converse_stream")
                        stream_response = self.client.converse_stream(**request)
                        logger.debug(f"Stream response received: {type(stream_response)}")
                        logger.debug(f"Stream response dir: {dir(stream_response)}")
                        
                        # Let's try to understand the structure better
                        if hasattr(stream_response, '__dict__'):
                            logger.debug(f"Stream response dict: {stream_response.__dict__}")
                        
                        # Process all streaming events
                        event_count = 0
                        has_content = False
                        
                        try:
                            for event in self._convert_streaming_response(stream_response):
                                event_count += 1
                                logger.debug(f"Yielding event {event_count}: {event}")
                                
                                # Check if we have actual content
                                if 'contentBlockDelta' in event and 'delta' in event['contentBlockDelta']:
                                    if 'text' in event['contentBlockDelta']['delta'] or 'toolUse' in event['contentBlockDelta']['delta']:
                                        has_content = True
                                
                                yield event
                        except Exception as stream_error:
                            logger.error(f"Error during streaming: {stream_error}")
                            logger.error(f"Stream error type: {type(stream_error)}")
                            raise stream_error
                        
                        logger.debug(f"Processed {event_count} streaming events, has_content: {has_content}")
                        
                        # If we didn't get any content, fallback to non-streaming
                        if event_count == 0 or not has_content:
                            logger.warning("No content received from streaming response, falling back to non-streaming")
                            response = self.client.converse(**request)
                            async for event in self._convert_non_streaming_to_streaming(response):
                                yield event
                                
                    except (AttributeError, Exception) as e:
                        # Fallback to non-streaming if converse_stream is not available or fails
                        logger.warning(f"converse_stream failed ({e}), falling back to non-streaming")
                        response = self.client.converse(**request)
                        async for event in self._convert_non_streaming_to_streaming(response):
                            yield event
                else:
                    # Non-streaming path
                    logger.debug("Using non-streaming converse API")
                    response = self.client.converse(**request)
                    async for event in self._convert_non_streaming_to_streaming(response):
                        yield event

            elif self._is_titan_embed_model():
                if streaming:
                    # Try streaming for Titan models
                    try:
                        logger.debug("Attempting to use invoke_model_with_response_stream for Titan")
                        stream_response = self.client.invoke_model_with_response_stream(**request)
                        
                        event_count = 0
                        for event in self._convert_streaming_response(stream_response):
                            event_count += 1
                            logger.debug(f"Yielding Titan event {event_count}: {event}")
                            yield event
                        
                        if event_count == 0:
                            logger.warning("No events from Titan streaming, falling back to non-streaming")
                            response = self.client.invoke_model(**request)
                            async for event in self._convert_non_streaming_to_streaming(response):
                                yield event
                                
                    except (AttributeError, Exception) as e:
                        logger.warning(f"Titan streaming failed ({e}), falling back to non-streaming")
                        response = self.client.invoke_model(**request)
                        async for event in self._convert_non_streaming_to_streaming(response):
                            yield event
                else:
                    # Non-streaming path for Titan
                    logger.debug("Using non-streaming invoke_model API for Titan")
                    response = self.client.invoke_model(**request)
                    async for event in self._convert_non_streaming_to_streaming(response):
                        yield event

        except Exception as e:
            error_message = str(e)

            # Handle throttling error
            if "ThrottlingException" in error_message:
                raise ModelThrottledException(error_message) from e

            # Handle context window overflow
            if any(
                overflow_message in error_message
                for overflow_message in CONTEXT_WINDOW_OVERFLOW_MESSAGES
            ):
                logger.warning("SAP GenAI Hub threw context window overflow error")
                raise ContextWindowOverflowException(e) from e

            # Otherwise raise the error
            raise e

    @override
    async def structured_output(
        self,
        output_model: Type[T],
        prompt: Messages,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Dict[str, Union[T, Any]], None]:
        """Get structured output from the model.

        Implements the Strands `Model.structured_output` contract: an async generator
        that streams model events and yields a final ``{"output": <instance>}`` event.
        This mirrors ``BedrockModel.structured_output`` so evaluators and agents that
        call ``agent(prompt, structured_output_model=...)`` work through the SAP GenAI
        Hub proxy.

        Args:
            output_model: The Pydantic model class that defines the output schema.
            prompt: The prompt messages to send to the model.
            system_prompt: Optional system prompt for additional context.
            **kwargs: Additional keyword arguments for future extensibility.

        Yields:
            Model events, with the last being ``{"output": output_model instance}``.

        Raises:
            ValueError: If the model does not return a valid tool use for the schema.
        """
        from strands.event_loop import streaming
        from strands.tools import convert_pydantic_to_tool_spec

        # Represent the schema as a tool the model is asked to call.
        tool_spec = convert_pydantic_to_tool_spec(output_model)

        response = self.stream(
            messages=prompt, tool_specs=[tool_spec], system_prompt=system_prompt
        )
        async for event in streaming.process_stream(response):
            yield event

        stop_reason, messages, _, _ = event["stop"]

        if stop_reason != "tool_use":
            raise ValueError(
                f'Model returned stop_reason: {stop_reason} instead of "tool_use".'
            )

        content = messages["content"]
        output_response: Optional[Dict[str, Any]] = None
        for block in content:
            # Match the tool use whose name is our schema tool; skip anything else.
            if block.get("toolUse") and block["toolUse"]["name"] == tool_spec["name"]:
                output_response = block["toolUse"]["input"]

        if output_response is None:
            raise ValueError(
                "No valid tool use or tool use input was found in the SAP GenAI Hub response."
            )

        yield {"output": output_model(**output_response)}
