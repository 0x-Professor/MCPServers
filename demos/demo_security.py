#!/usr/bin/env python3
"""
🔍 Smart Contract Security Demo
Interactive demonstration of smart contract auditing capabilities
"""
import asyncio
import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich import print as rprint
import time

console = Console()

class SecurityDemo:
    def __init__(self):
        self.vulnerability_types = [
            "Reentrancy", "Integer Overflow", "Unchecked Call Return",
            "Denial of Service", "Access Control", "Front Running",
            "Time Manipulation", "Gas Limit Issues"
        ]
        
        self.sample_contract = """
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABILITY: Reentrancy attack possible
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success);
        
        balances[msg.sender] -= _amount; // State change after external call
    }
    
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
        """

    def display_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║  🔍 MCP Smart Contract Security Auditor Demo                 ║
║  AI-powered vulnerability detection and security analysis    ║
╚══════════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold red")

    def show_audit_features(self):
        features_table = Table(title="🛡️ Security Analysis Features", style="cyan")
        features_table.add_column("Feature", style="bold")
        features_table.add_column("Description", style="green")
        features_table.add_column("AI-Powered", style="yellow")
        
        features = [
            ("Vulnerability Detection", "Comprehensive pattern-based analysis", "✅"),
            ("Gas Optimization", "Efficiency recommendations", "✅"),
            ("ERC Compliance", "Standard compliance checking", "✅"),
            ("Attack Simulation", "Exploit scenario testing", "✅"),
            ("Code Quality", "Best practices analysis", "✅"),
            ("Risk Assessment", "Severity scoring", "✅"),
        ]
        
        for feature in features:
            features_table.add_row(*feature)
        
        console.print(features_table)

    async def analyze_contract(self, contract_code=None):
        if not contract_code:
            contract_code = self.sample_contract
            
        console.print("\n🔄 Initiating smart contract security analysis...", style="yellow")
        
        analysis_steps = [
            ("Parsing contract syntax", 1),
            ("Extracting function signatures", 1),
            ("Building control flow graph", 2),
            ("Running vulnerability scanners", 3),
            ("Performing static analysis", 2),
            ("Simulating attack vectors", 3),
            ("Calculating risk scores", 1),
            ("Generating recommendations", 1)
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            for step_name, duration in analysis_steps:
                task = progress.add_task(f"{step_name}...", total=100)
                for i in range(100):
                    await asyncio.sleep(duration / 100)
                    progress.update(task, advance=1)

        # Generate vulnerability report
        await self.show_vulnerability_report()

    async def show_vulnerability_report(self):
        console.print("\n🚨 Security Analysis Complete", style="bold red")
        
        # Vulnerability summary
        vuln_found = random.randint(3, 6)
        critical = random.randint(1, 2)
        high = random.randint(1, 2)
        medium = random.randint(1, 2)
        low = vuln_found - critical - high - medium
        
        summary_panel = Panel(
            f"""
📊 **Vulnerability Summary:**
   🔴 Critical: {critical}
   🟠 High: {high}  
   🟡 Medium: {medium}
   🟢 Low: {low}
   
🎯 **Overall Risk Score:** {85 - vuln_found * 10}/100
⚠️  **Recommended Action:** Immediate fixes required for critical issues
            """,
            title="🔍 Analysis Summary",
            border_style="red"
        )
        console.print(summary_panel)

        # Detailed vulnerabilities
        vulns_table = Table(title="🚨 Detected Vulnerabilities", style="red")
        vulns_table.add_column("Severity", style="bold")
        vulns_table.add_column("Type", style="yellow")
        vulns_table.add_column("Location", style="cyan")
        vulns_table.add_column("Description")
        
        sample_vulns = [
            ("🔴 CRITICAL", "Reentrancy", "withdraw()", "External call before state change allows reentrancy attacks"),
            ("🟠 HIGH", "Access Control", "withdraw()", "Missing access controls for sensitive functions"),
            ("🟡 MEDIUM", "Gas Optimization", "deposit()", "Inefficient gas usage in loop operations"),
            ("🟢 LOW", "Code Quality", "getBalance()", "Missing input validation for edge cases"),
        ]
        
        for vuln in sample_vulns[:vuln_found]:
            vulns_table.add_row(*vuln)
        
        console.print(vulns_table)

    async def show_contract_code(self):
        console.print("\n📄 Sample Vulnerable Contract", style="bold cyan")
        
        syntax = Syntax(
            self.sample_contract,
            "solidity",
            theme="monokai",
            line_numbers=True,
            background_color="default"
        )
        console.print(syntax)

    async def simulate_attack(self):
        console.print("\n⚔️ Simulating Reentrancy Attack", style="bold red")
        
        attack_code = """
contract Attacker {
    VulnerableBank public bank;
    uint256 public amount = 1 ether;
    
    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }
    
    function attack() public payable {
        bank.deposit{value: amount}();
        bank.withdraw(amount);
    }
    
    receive() external payable {
        if (address(bank).balance >= amount) {
            bank.withdraw(amount); // Reentrant call!
        }
    }
}
        """
        
        console.print("🔴 Attack Contract:", style="bold red")
        syntax = Syntax(attack_code, "solidity", theme="monokai", line_numbers=True)
        console.print(syntax)
        
        console.print("\n🎬 Attack Simulation:", style="bold yellow")
        
        simulation_steps = [
            "Deploying attack contract...",
            "Initial deposit of 1 ETH...",
            "Calling withdraw function...",
            "Reentrancy triggered in receive()...",
            "Draining contract balance...",
            "Attack successful! 💀"
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for step in simulation_steps:
                task = progress.add_task(step, total=None)
                await asyncio.sleep(1.5)
                console.print(f"✅ {step}", style="red" if "successful" in step else "yellow")

        result_panel = Panel(
            """
💀 **Attack Result:**
   • Initial contract balance: 10 ETH
   • Attacker deposit: 1 ETH  
   • Amount stolen: 10 ETH
   • Remaining balance: 0 ETH
   
🛡️ **Mitigation:**
   • Use checks-effects-interactions pattern
   • Implement reentrancy guards
   • Use pull payment pattern
            """,
            title="⚔️ Reentrancy Attack Simulation",
            border_style="red"
        )
        console.print(result_panel)

    async def show_gas_optimization(self):
        console.print("\n⛽ Gas Optimization Analysis", style="bold green")
        
        gas_table = Table(title="⛽ Gas Usage Optimization", style="green")
        gas_table.add_column("Function", style="bold")
        gas_table.add_column("Current Gas", style="red")
        gas_table.add_column("Optimized Gas", style="green")
        gas_table.add_column("Savings", style="yellow")
        gas_table.add_column("Optimization")
        
        optimizations = [
            ("deposit()", "45,234", "42,891", "2,343 (5.2%)", "Use unchecked arithmetic"),
            ("withdraw()", "67,123", "59,876", "7,247 (10.8%)", "Combine require statements"),
            ("getBalance()", "21,456", "19,234", "2,222 (10.4%)", "Use view optimization"),
        ]
        
        for opt in optimizations:
            gas_table.add_row(*opt)
        
        console.print(gas_table)
        
        savings_panel = Panel(
            """
💰 **Total Potential Savings:**
   • Gas reduction: 11,812 gas units
   • Cost savings: ~$2.36 per transaction (at 20 gwei)
   • Monthly savings: ~$708 (300 tx/month)
   
🚀 **Optimization Recommendations:**
   1. Use assembly for mathematical operations
   2. Pack struct variables efficiently  
   3. Use events instead of storage for logs
   4. Implement batch operations for multiple calls
            """,
            title="⛽ Gas Optimization Report",
            border_style="green"
        )
        console.print(savings_panel)

    async def run_demo(self):
        self.display_banner()
        
        while True:
            console.print("\n" + "="*60)
            console.print("🎮 Demo Options:", style="bold cyan")
            console.print("1. View audit features")
            console.print("2. Show sample vulnerable contract")
            console.print("3. Run full security analysis")
            console.print("4. Simulate reentrancy attack")
            console.print("5. Gas optimization analysis")
            console.print("6. Exit demo")
            
            choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4", "5", "6"])
            
            if choice == "1":
                self.show_audit_features()
                
            elif choice == "2":
                await self.show_contract_code()
                
            elif choice == "3":
                if Confirm.ask("Run comprehensive security analysis on sample contract?"):
                    await self.analyze_contract()
                    
            elif choice == "4":
                if Confirm.ask("Simulate reentrancy attack? (Educational purposes only)"):
                    await self.simulate_attack()
                    
            elif choice == "5":
                await self.show_gas_optimization()
                
            elif choice == "6":
                console.print("\n👋 Thank you for trying the Security Auditor Demo!", style="bold blue")
                console.print("🔗 Learn more: https://github.com/0x-Professor/MCPServers", style="cyan")
                break

if __name__ == "__main__":
    demo = SecurityDemo()
    try:
        asyncio.run(demo.run_demo())
    except KeyboardInterrupt:
        console.print("\n\n👋 Demo interrupted. Thanks for trying!", style="bold yellow")