"""MCP Persistent Session Manager 

A utility class that manages persistent MCP client sessions across Jupyter cells,
eliminating the need for 'with' context managers in each cell.

Usage:
    from util.mcp_session_manager import MCPSessionManager
    
    mcp_manager = MCPSessionManager()
    mcp_manager.start_sessions({
        "financial": "http://127.0.0.1:8001/mcp",
        "simple": "http://127.0.0.1:8002/mcp"
    })
    
    tools = mcp_manager.get_tools("simple")
    agent = Agent(model=model, tools=tools)  # Works across cells
    
    mcp_manager.cleanup_all()  # Clean shutdown
"""

import logging
from typing import Dict, List, Any, Optional
from contextlib import ExitStack

try:
    from strands.tools.mcp import MCPClient
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:
    raise ImportError(
        "MCP dependencies not found. Please install strands-agents with MCP support."
    )

logger = logging.getLogger(__name__)


class MCPSessionManager:
    """Manages persistent MCP client sessions across Jupyter cell boundaries."""
    
    def __init__(self):
        """Initialize the session manager."""
        self._active_sessions: Dict[str, MCPClient] = {}
        self._cached_tools: Dict[str, List[Any]] = {}
        self._context_stack = ExitStack()
        self._session_urls: Dict[str, str] = {}
        
    def start_sessions(self, server_configs: Dict[str, str]) -> None:
        """Start persistent sessions for multiple MCP servers.
        
        Args:
            server_configs: Dictionary mapping server names to MCP URLs
                          Example: {"financial": "http://127.0.0.1:8001/mcp"}
        """
        for server_name, url in server_configs.items():
            try:
                logger.info(f"Starting MCP session for {server_name} at {url}")
                
                # Create MCP client
                mcp_client = MCPClient(lambda url=url: streamablehttp_client(url))
                
                # Enter the context and keep it alive using ExitStack
                self._context_stack.enter_context(mcp_client)
                
                # Store session references
                self._active_sessions[server_name] = mcp_client
                self._session_urls[server_name] = url
                
                logger.info(f"✅ MCP session active for {server_name}")
                
            except Exception as e:
                logger.error(f"Failed to start MCP session for {server_name}: {e}")
                # Continue with other sessions
                continue
    
    def get_tools(self, server_name: str) -> List[Any]:
        """Get tools for a specific MCP server.
        
        Returns session-bound tools that maintain their MCP client connection.
        
        Args:
            server_name: Name of the server to get tools from
            
        Returns:
            List of tools that are bound to the persistent MCP session
        """

        if server_name not in self._active_sessions:
            logger.error(f"No active session found for {server_name}")
            return []
        
        # Check cache first
        if server_name in self._cached_tools:
            logger.info(f"Retrieved {len(self._cached_tools[server_name])} tools from {server_name} (cached)")
            return self._cached_tools[server_name]
        
        try:
            # Get the active MCP client
            mcp_client = self._active_sessions[server_name]
            
            # This ensures tools maintain their connection to the persistent session
            tools = mcp_client.list_tools_sync()
            
            # Cache the session-bound tools
            self._cached_tools[server_name] = tools
            
            logger.info(f"Retrieved {len(tools)} tools from {server_name}")
            return tools
            
        except Exception as e:
            logger.error(f"Failed to get tools from {server_name}: {e}")
            return []
    
    def get_all_tools(self) -> List[Any]:
        """Get all tools from all active sessions.
        
        Returns:
            Combined list of all session-bound tools
        """
        all_tools = []
        for server_name in self._active_sessions.keys():
            tools = self.get_tools(server_name)
            all_tools.extend(tools)
        return all_tools
    
    def is_session_active(self, server_name: str) -> bool:
        """Check if a session is currently active.
        
        Args:
            server_name: Name of the server to check
            
        Returns:
            True if session is active, False otherwise
        """
        return server_name in self._active_sessions
    
    def get_active_sessions(self) -> List[str]:
        """Get list of all active session names.
        
        Returns:
            List of active session names
        """
        return list(self._active_sessions.keys())
    
    def cleanup_session(self, server_name: str) -> bool:
        """Clean up a specific session.
        
        Args:
            server_name: Name of the server session to clean up
            
        Returns:
            True if cleanup successful, False otherwise
        """
        if server_name not in self._active_sessions:
            logger.warning(f"No active session found for {server_name}")
            return False
        
        try:
            # Remove from active sessions
            del self._active_sessions[server_name]
            
            # Clear cached tools
            if server_name in self._cached_tools:
                del self._cached_tools[server_name]
            
            # Remove URL mapping
            if server_name in self._session_urls:
                del self._session_urls[server_name]
            
            logger.info(f"Cleaned up session for {server_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup session for {server_name}: {e}")
            return False
    
    def cleanup_all(self) -> None:
        """Clean up all active sessions and resources."""
        try:
            # Clear all session references
            self._active_sessions.clear()
            self._cached_tools.clear()
            self._session_urls.clear()
            
            # Close all contexts in the ExitStack
            self._context_stack.close()
            
            # Recreate ExitStack for future use
            self._context_stack = ExitStack()
            
            logger.info("All MCP sessions cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get detailed information about all sessions.
        
        Returns:
            Dictionary with session information
        """
        session_info = {
            "total_sessions": len(self._active_sessions),
            "active_sessions": list(self._active_sessions.keys()),
            "session_urls": self._session_urls.copy(),
            "cached_tools_count": {
                name: len(tools) for name, tools in self._cached_tools.items()
            }
        }
        return session_info