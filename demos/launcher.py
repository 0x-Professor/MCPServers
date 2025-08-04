#!/usr/bin/env python3
"""
🎮 MCP Servers Demo Launcher
Interactive launcher for all available demonstrations
"""
import os
import sys
import subprocess
import webbrowser
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import print as rprint

console = Console()

class DemoLauncher:
    def __init__(self):
        self.demos_dir = Path(__file__).parent
        self.root_dir = self.demos_dir.parent
        
        self.demos = {
            "1": {
                "name": "🌉 Cross-Chain Bridge Demo",
                "description": "Experience seamless multi-chain asset transfers",
                "script": "demo_bridge.py",
                "type": "interactive"
            },
            "2": {
                "name": "🔍 Smart Contract Security Demo", 
                "description": "AI-powered vulnerability detection and analysis",
                "script": "demo_security.py", 
                "type": "interactive"
            },
            "3": {
                "name": "🎬 Interactive Web Showcase",
                "description": "Animated web demo with blockchain visualizations",
                "script": "../docs/showcase.html",
                "type": "web"
            },
            "4": {
                "name": "📊 Innovation Portfolio",
                "description": "Complete project timeline and achievements",
                "script": "../docs/portfolio.md",
                "type": "markdown"
            },
            "5": {
                "name": "🛡️ Live MCP Server",
                "description": "Start Cross-Chain Bridge MCP Server",
                "script": "../BlockChain/cross_chain_bridge_assistant",
                "type": "server"
            }
        }

    def display_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║  🎮 MCP Servers Demo Launcher                                ║
║  Choose your adventure into the future of blockchain & AI    ║
╚══════════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold blue")

    def show_demo_menu(self):
        table = Table(title="🚀 Available Demonstrations", style="cyan")
        table.add_column("ID", style="bold", width=4)
        table.add_column("Demo", style="green", width=35)
        table.add_column("Type", style="yellow", width=12)
        table.add_column("Description", style="white")
        
        for demo_id, demo_info in self.demos.items():
            table.add_row(
                demo_id,
                demo_info["name"],
                demo_info["type"].title(),
                demo_info["description"]
            )
        
        console.print(table)

    def check_dependencies(self):
        """Check if required dependencies are installed"""
        try:
            import rich
            return True
        except ImportError:
            console.print("❌ Missing dependencies. Installing...", style="yellow")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                console.print("✅ Dependencies installed successfully!", style="green")
                return True
            except subprocess.CalledProcessError:
                console.print("❌ Failed to install dependencies", style="red")
                return False

    def launch_interactive_demo(self, script_name):
        """Launch a Python interactive demo"""
        script_path = self.demos_dir / script_name
        if not script_path.exists():
            console.print(f"❌ Demo script not found: {script_path}", style="red")
            return False
            
        console.print(f"🚀 Launching {script_name}...", style="green")
        try:
            subprocess.run([sys.executable, str(script_path)], cwd=self.demos_dir)
            return True
        except KeyboardInterrupt:
            console.print("\n👋 Demo interrupted by user", style="yellow")
            return True
        except Exception as e:
            console.print(f"❌ Error launching demo: {e}", style="red")
            return False

    def launch_web_demo(self, html_path):
        """Launch web-based demo in browser"""
        full_path = self.demos_dir / html_path
        if not full_path.exists():
            console.print(f"❌ Web demo not found: {full_path}", style="red")
            return False
            
        console.print("🌐 Opening web demo in browser...", style="green")
        try:
            webbrowser.open(f"file://{full_path.absolute()}")
            console.print("✅ Web demo opened successfully!", style="green")
            return True
        except Exception as e:
            console.print(f"❌ Error opening web demo: {e}", style="red")
            return False

    def launch_server_demo(self, server_path):
        """Launch MCP server demo"""
        full_path = self.demos_dir / server_path
        if not full_path.exists():
            console.print(f"❌ Server path not found: {full_path}", style="red")
            return False
            
        console.print("🔧 Starting MCP Server...", style="green")
        console.print("📍 Server will be available at: http://localhost:3001", style="cyan")
        console.print("Press Ctrl+C to stop the server", style="yellow")
        
        try:
            # Change to server directory and run
            os.chdir(full_path)
            subprocess.run(["uv", "run", "mcp", "dev", "server/server.py"])
            return True
        except KeyboardInterrupt:
            console.print("\n🛑 Server stopped by user", style="yellow")
            return True
        except Exception as e:
            console.print(f"❌ Error starting server: {e}", style="red")
            console.print("💡 Make sure you have 'uv' installed and dependencies set up", style="yellow")
            return False

    def view_markdown(self, md_path):
        """Display markdown content or open in browser"""
        full_path = self.demos_dir / md_path
        if not full_path.exists():
            console.print(f"❌ Markdown file not found: {full_path}", style="red")
            return False
            
        console.print("📖 Opening portfolio document...", style="green")
        try:
            if sys.platform.startswith('win'):
                os.startfile(full_path)
            elif sys.platform.startswith('darwin'):
                subprocess.run(['open', full_path])
            else:
                subprocess.run(['xdg-open', full_path])
            console.print("✅ Portfolio opened successfully!", style="green")
            return True
        except Exception as e:
            console.print(f"❌ Error opening portfolio: {e}", style="red")
            return False

    def run_launcher(self):
        self.display_banner()
        
        # Check dependencies
        if not self.check_dependencies():
            return
        
        while True:
            console.print("\n" + "="*60)
            self.show_demo_menu()
            
            console.print("\n🎯 Additional Options:", style="bold cyan")
            console.print("6. 🔧 Install Demo Dependencies")
            console.print("7. 📚 View Documentation")  
            console.print("8. 🏠 Return to Main Repository")
            console.print("9. 🚪 Exit Launcher")
            
            choice = Prompt.ask("\nSelect a demo or option", choices=[str(i) for i in range(1, 10)])
            
            if choice in self.demos:
                demo = self.demos[choice]
                console.print(f"\n🎮 Starting: {demo['name']}", style="bold green")
                
                if demo["type"] == "interactive":
                    self.launch_interactive_demo(demo["script"])
                elif demo["type"] == "web":
                    self.launch_web_demo(demo["script"])
                elif demo["type"] == "server":
                    self.launch_server_demo(demo["script"])
                elif demo["type"] == "markdown":
                    self.view_markdown(demo["script"])
                    
            elif choice == "6":
                console.print("🔧 Installing demo dependencies...", style="yellow")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                    console.print("✅ Dependencies installed successfully!", style="green")
                except subprocess.CalledProcessError:
                    console.print("❌ Failed to install dependencies", style="red")
                    
            elif choice == "7":
                console.print("📚 Opening documentation...", style="cyan")
                docs_path = self.root_dir / "README.md"
                try:
                    if sys.platform.startswith('win'):
                        os.startfile(docs_path)
                    elif sys.platform.startswith('darwin'):
                        subprocess.run(['open', docs_path])
                    else:
                        subprocess.run(['xdg-open', docs_path])
                except Exception as e:
                    console.print(f"❌ Error opening docs: {e}", style="red")
                    
            elif choice == "8":
                console.print("🏠 Returning to main repository...", style="cyan")
                os.chdir(self.root_dir)
                console.print(f"📍 Current directory: {os.getcwd()}", style="green")
                
            elif choice == "9":
                console.print("\n👋 Thank you for exploring MCP Servers!", style="bold blue")
                console.print("🌟 Star us on GitHub: https://github.com/0x-Professor/MCPServers", style="cyan")
                console.print("🚀 Join the revolution in decentralized computing!", style="green")
                break

if __name__ == "__main__":
    launcher = DemoLauncher()
    try:
        launcher.run_launcher()
    except KeyboardInterrupt:
        console.print("\n\n👋 Launcher interrupted. Thanks for exploring!", style="bold yellow")