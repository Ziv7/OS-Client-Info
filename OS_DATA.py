import subprocess
import platform
import os

def run_command(command):
    """Execute a command in the shell and return its output."""
    try:
        return subprocess.check_output(command, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

def get_system_information():
    os_info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "hostname": platform.node(),
        "working_directory": os.getcwd(),
        "user": os.getlogin(),  # Current user
        "architecture": platform.architecture()[0],  # System architecture
        "python_version": platform.python_version()  # Python version
    }

    # Gather OS information
    if os_info['system'] == "Linux":
        # General distribution info
        os_info['distribution_info'] = run_command("lsb_release -a")  
        os_info['cpu_info'] = run_command("lscpu")
        os_info['memory_info'] = run_command("free -h")
        os_info['disk_info'] = run_command("df -h")
        os_info['network_info'] = run_command("ifconfig")
        os_info['processes'] = run_command("ps aux")  # List all running processes
        os_info['top_running_processes'] = run_command("top -b -n 1 | head")  # Top processes
        os_info['logged_in_users'] = run_command("who")  # Who is logged in
        os_info['mounted_filesystems'] = run_command("mount")  # Mounted filesystems
        os_info['environment_variables'] = run_command("env")  # Environment variables
        os_info['system_uptime'] = run_command("uptime")  # System uptime
        os_info['system_services'] = run_command("systemctl list-units --type=service")  # System services
        os_info['last_boot_time'] = run_command("who -b")  # Last boot time
        os_info['open_network_connections'] = run_command("ss -tuln")  # Open network connections
        os_info['directory_structure'] = run_command("tree -L 0 /")  # Directory structure, root
        os_info['logins_last'] = run_command("last")  # Login history
        os_info['cron_jobs'] = run_command("crontab -l")  # Cron jobs for current user

    elif os_info['system'] == "Windows":
        os_info['system_info'] = run_command("systeminfo")  
        os_info['cpu_info'] = run_command("wmic cpu get name")
        os_info['memory_info'] = run_command('powershell -command "Get-WmiObject Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | Format-Table -AutoSize"')  # Memory information
        os_info['disk_info'] = run_command("wmic logicaldisk get name,size,freespace")
        os_info['network_info'] = run_command("ipconfig")
        os_info['processes'] = run_command("tasklist")  # List running processes
        os_info['top_running_processes'] = run_command("powershell -command \"Get-Process | Sort-Object CPU -Descending | Select-Object -First 10\"")  # Top processes
        os_info['logged_in_users'] = run_command("powershell -command \"Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName\"")  # Current logged-in user # ALL USERS -- os_info['logged_in_users'] = run_command("powershell -command \"query user\"")
        os_info['system_uptime'] = run_command("wmic os get lastbootuptime")  # Last boot time
        os_info['open_network_connections'] = run_command("netstat -an")  # Open network connections
        os_info['user_profile_directory'] = run_command("echo %USERPROFILE%")  # User Profile directory
        os_info['installed_programs'] = run_command("wmic product get name,version")  # List installed programs
        os_info['environment_variables'] = run_command("set")  # Environment variables
        os_info['directory_structure'] = run_command('powershell -command "Get-PSDrive -PSProvider FileSystem | ForEach-Object { Get-ChildItem $_.Root -Recurse -Depth 0 }"')  # Directory structure limited to 2 levels from each drive
        os_info['scheduled_tasks'] = run_command("schtasks /query")  # Scheduled tasks

    elif os_info['system'] == "Darwin":  # macOS
        os_info['system_info'] = run_command("sw_vers")
        os_info['cpu_info'] = run_command("sysctl -n machdep.cpu.brand_string")
        os_info['memory_info'] = run_command("vm_stat")
        os_info['disk_info'] = run_command("df -h")
        os_info['network_info'] = run_command("ifconfig")
        os_info['processes'] = run_command("ps aux")  # List all running processes
        os_info['top_running_processes'] = run_command("top -l 10")  # Top processes
        os_info['logged_in_users'] = run_command("who")  # Logged in users
        os_info['system_uptime'] = run_command("uptime")  # System uptime
        os_info['open_network_connections'] = run_command("netstat -an")  # Open network connections
        os_info['user_home_directory'] = run_command("echo $HOME")  # User home directory
        os_info['directory_structure'] = run_command("ls -R | head -n 50")  # Directory structure recursively
        os_info['environment_variables'] = run_command("printenv")  # Environment variables
        os_info['cron_jobs'] = run_command("crontab -l")  # Cron jobs for current user

    else:
        return "Unsupported OS"

    return os_info

def display_system_information(info):
    """Display the gathered system information in an organized manner with detailed descriptions."""
    output = []
    
    # System Information
    output.append("=== System Information ===")
    output.append("This section provides general information about the operating system and environment used.")
    output.append("")
    output.append(f"Operating System: {info['system']} (The type of operating system, e.g., Windows, Linux, macOS)")
    output.append(f"Release: {info['release']} (The specific version of the operating system)")
    output.append(f"Version: {info['version']} (More detailed version information including build)")
    output.append(f"Hostname: {info['hostname']} (The network name of this computer)")
    output.append(f"Working Directory: {info['working_directory']} (The current directory from which the script is being run)")
    output.append(f"Current User: {info['user']} (The user currently logged into the system)")
    output.append(f"Architecture: {info['architecture']} (The system architecture, e.g., x86, x64)")
    output.append(f"Python Version: {info['python_version']} (The version of Python currently in use)")
    output.append("")  # Empty line for spacing
    
    # Additional OS Information
    output.append("=== Additional OS Information ===")
    output.append("This section provides miscellaneous details about the operating system.")
    output.append("")
    output.append(info.get('additional_info', 'N/A'))
    output.append("")  # Empty line for spacing

    # CPU Information
    output.append("=== CPU Information ===")
    output.append("Details about the central processing unit (CPU) of the system.")
    output.append("")
    output.append(info.get('cpu_info', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Memory Information
    output.append("=== Memory Information ===")
    output.append("Information about the system's RAM, including total and available memory.")
    output.append("")
    output.append(info.get('memory_info', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Disk Information
    output.append("=== Disk Information ===")
    output.append("Details about the hard drives, including size and available space.")
    output.append("")
    output.append(info.get('disk_info', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Network Information
    output.append("=== Network Information ===")
    output.append("Information about the network interfaces and their configurations.")
    output.append("")
    output.append(info.get('network_info', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Running Processes
    output.append("=== Running Processes ===")
    output.append("A list of currently active processes running on the system.")
    output.append("")
    output.append(info.get('processes', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Top Running Processes
    output.append("=== Top Running Processes ===")
    output.append("Displays the processes consuming the most CPU resources.")
    output.append("")
    output.append(info.get('top_running_processes', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Logged In Users
    output.append("=== Logged In Users ===")
    output.append("Displays users currently signed into the system.")
    output.append("")
    output.append(info.get('logged_in_users', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # System Uptime
    output.append("=== System Uptime ===")
    output.append("Shows how long the system has been running since the last reboot.")
    output.append("")
    output.append(info.get('system_uptime', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Open Network Connections
    output.append("=== Open Network Connections ===")
    output.append("Information about current network connections and their statuses.")
    output.append("")
    output.append(info.get('open_network_connections', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # User Home Directory
    output.append("=== User Home Directory ===")
    output.append("Path to the home directory of the current user.")
    output.append("")
    output.append(info.get('user_home_directory', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Directory Structure
    output.append("=== Directory Structure (up to 3 levels) ===")
    output.append("A view of the directory tree structure, limited to 3 levels deep.")
    output.append("")
    output.append(info.get('directory_structure', 'N/A'))
    output.append("")  # Empty line for spacing
    
    # Environment Variables
    output.append("=== Environment Variables ===")
    output.append("A list of environment variables that affect the behavior of the system and applications.")
    output.append("")
    output.append(info.get('environment_variables', 'N/A'))
    output.append("")  # Empty line for spacing

    # User Profile Directory
    output.append("=== User Profile Directory ===")
    output.append("Path to the home directory of the current user.")
    output.append("")  # Spacing
    output.append(info.get('user_profile_directory', 'N/A'))  # Pulling in user home directory
   

    # Installed Programs
    output.append("=== Installed Programs ===")
    output.append("A list of software installed on this system with their version information.")
    output.append("")  # Spacing
    output.append(info.get('installed_programs', 'N/A'))  # Pulling in installed programs
    
    
    # Cron Jobs
    output.append("=== Cron Jobs ===")
    output.append("Lists any scheduled tasks for the current user, which run at specified intervals.")
    output.append("")
    output.append(info.get('cron_jobs', 'N/A'))
    output.append("")  # Empty line for spacing

    # Conclude the output
    output.append("=== End of System Information ===")
    output.append("This concludes the detailed system information output.")
    output.append("")
    
    # Print the complete output
    print("\n".join(output))
    # Additional Sections can be appended as needed

if __name__ == "__main__":
    system_info = get_system_information()
    display_system_information(system_info)
    input("\nPress Enter to continue...")