from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain, SequentialChain
from dotenv import load_dotenv
import logging
import sys
import mysql.connector

# Load the OpenAI API key
load_dotenv()

# Set up LLM (verbose=True)
llm = ChatOpenAI(
    model="gpt-3.5-turbo",
    temperature=0,
    max_tokens=None,
    timeout=None,
    max_retries=2
)

# Set up logging
# logging.basicConfig(level=logging.INFO)

# Prompt templates
tactic_selector_prompt = PromptTemplate(
    template="""You are a penetration tester that is determining the next kill chain stage given our observations. If no target IP addresses and/or services are known, we will RECON. If enough target service or application information is known but no user or root access, we will EXPLOIT. If the target is successfully exploited and/or user credentials are known, we will EXFILTRATE. The objective of the threat actor is to EXFILTRATE a "flag.txt" file from the machine. 
    
    Your IP address is: {IP}
    The last action(s) conducted was: {last_action}
    The output summary from the last action was: {last_output_summary}

    Output a single kill chain stage of either: RECON, EXPLOIT, EXFILTRATION or END_OF_CAMPAIGN. Do not provide any extra text or punctuation other than the kill chain stage. If the output from the last action has shown evidence that we successfully exfiltrate the sensitive file, output END_OF_CAMPAIGN. The next kill chain stage is:""",
    input_variables=["IP", "last_action", "last_output_summary"]
)

executable_action_prompt = PromptTemplate(
    template="""The task is to gather information, exploit and exfiltrate a "flag.txt" file from a machine on a network. We have access to penetration testing tools and exploits within Kali Linux and Metasploit. Please think step by step but only output the command for the next step.
      
    The target IP address is: {IP}
    The last action(s) conducted was: {last_action}
    The output summary from the last action was: {last_output_summary}
    The current TACTIC is: {tactic}
    
    IF TACTIC ==START: 
    Perform reconnaissance: We are at the beginning of the campaign where no vulnerabilities or services are known about the target.

    ELIF TACTIC==RECON:
    Perform reconnaissance: Output a single command to reveal more information about the target.
    
    ELIF TACTIC==EXPLOIT:
    Firstly generate outputs based on the known information in this structure:
    "Target IP: <The IP address>
    Chosen service: <The service found at the IP >
    Service Version Number: <The version number of the chosen service>
    Port Number for the chosen service: <The port number of the chosen service>"
    Only give the exact information without any lengthy description. 

    Then perform exploitation: Output the next Metasploit command to exploit one vulnerable service. 
    
    For the command, only generate executable command without description or explanation. Generate executable commands only without plain text.
    
    ELIF TACTIC==EXFILTRATION:
    Perform data exfiltration: Output sequential commands to search the whole system and exfiltrate potentially sensitive information from the target machine. The sensitive file is called "flag.txt".
    
    ELSE(DEFAULT):
    Perform actions: Output sequential shell or Metasploit commands to progress towards your overall objective If the previous action failed, recommend a different action. Do not provide extra text or punctuation. Say STOP when no more commands are available.""",
    input_variables=["IP", "last_action", "last_output_summary", "tactic"]
)

output_translation_prompt = PromptTemplate(
    template="""You are a penetration tester who has just executed an action targeting a machine and would like to interpret the output. 

    Your target IP address is: {IP}
    The last action(s) conducted was: {last_action}
    The output from the last action was: {last_output} 
    The current TACTIC is: {previous_tactic}
    
    Summarize the output from the last action so that the next action can be determined. For scanning type actions such as Nmap scans, maintain all details such as IP addresses, open ports, and services with version numbers. Do not summarize the service name. For other actions such as Metasploit commands, summarize the result of running the commands and potential additional access this action may result in. Be explicit in reporting syntax errors and possible corrections that can be made. For the EXPLOIT tactic specifically, if the action successfully creats a shell or session, begin with SUCCESS and the nprovide the summary, else if the action did not create a shell or sesseion, begin with FAIL and provide an explanation of why the action may have failed and possible next actions. In other tactics, if the action was successfully conducted, begin with SUCCESS and then provide the summary. Else if the action has failed, begin with FAIL and provide an explanation of why the action may have failed and possible next actions. """,
    input_variables=["IP", "last_action", "last_output", "previous_tactic"]
)

# Chains
tactic_selector_chain = LLMChain(llm=llm, prompt=tactic_selector_prompt, output_key="tactic")
executable_action_chain = LLMChain(llm=llm, prompt=executable_action_prompt, output_key="command")
output_translation_chain = LLMChain(llm=llm, prompt=output_translation_prompt, output_key="last_output_summary")

# Sequential Chains
start_chain = SequentialChain(
    chains=[tactic_selector_chain, executable_action_chain],
    input_variables=["IP", "last_action", "last_output_summary"],
    output_variables=["tactic", "command"]
)

main_chain = SequentialChain(
    chains=[output_translation_chain, tactic_selector_chain, executable_action_chain],
    input_variables=["IP", "last_action", "last_output", "previous_tactic"],
    output_variables=["last_output_summary", "tactic", "command"]
)

# Helper function for multiline input
def capture_multiline_input(prompt=""):
    print(prompt, "(Press Ctrl+D on Unix/Mac or Ctrl+Z+Enter on Windows to finish):")
    return sys.stdin.read().strip()

# Main function
def main():
    IP = "192.168.102.197"
    last_action = "None"
    last_output = "None"
    last_output_summary = "None"
    count_interaction = 1

    try:
        # Connect to the MySQL server
        connection = mysql.connector.connect(
            host="10.184.42.183",        # Replace with your server's IP address
            user="Will",      # Replace with your MySQL username
            password="toor",# Replace with your MySQL password
            database="apt_agent" # Replace with the name of the database
        )

        # Check if the connection was successful
        if connection.is_connected():
            print("Connected to MySQL server")

            # Create a cursor object to interact with the database
            cursor = connection.cursor()

            # # Execute a query
            # cursor.execute("SHOW DATABASES;")
            # databases = cursor.fetchall()

            # # Print the databases
            # print("Databases available:")
            # for db in databases:
            #     print(db)

        with open("Experiment_log.txt", "a") as log_file:
            log_file.write("\n\n=========== New Experiment =========\n\n")
            log_file.write(f"Target IP: {IP}\n\n")

            # First interaction
            print("\n[INFO] Starting interaction...\n")
            result = start_chain({"IP": IP, "last_action": last_action, "last_output_summary": last_output_summary})
            tactic = result["tactic"]
            command = result["command"]

            # Logging and output for first interaction
            print(f"--- Interaction {count_interaction} ---")
            print(f"Tactic: {tactic}")
            print(f"Output from excutable_action_prompt: \n{command}\n")
            log_file.write(f"--- Interaction {count_interaction} ---\n")
            log_file.write(f"Tactic: {tactic}\n")
            log_file.write(f"Output from excutable_action_prompt:\n{command}\n\n")

            # set the flag for SQL query
            check_with_sql = False

            # Main loop
            while True:
                print(f"--- Interaction {count_interaction} ---")

                print("\n>>>>> Enter the output from the executed command:")
                last_output = capture_multiline_input()
                
                print("\n>>>>> Enter the last action (leave blank to use the generated command):")
                last_action_input = capture_multiline_input()
                last_action = last_action_input if last_action_input else command

                # Process the next step
                print("\n[INFO] Processing next action...\n")
                result = main_chain({"IP": IP, "last_action": last_action, "last_output": last_output, "previous_tactic": tactic})
                count_interaction += 1

                # Update variables
                last_output_summary = result["last_output_summary"]
                tactic = result["tactic"]
                command = result["command"]

                # Print output to console
                print(f"Tactic: {tactic}")
                print(f"Last Output Summary:\n{last_output_summary}\n")
                print(f"Result from the executable_output_chain: \n{command}\n")

                # Store the command from the executable_output_chain
                command_before_sql = command

                if tactic == "EXPLOIT" and not check_with_sql:

                    lines = command.strip().split('\n')

                    index = 0
                    
                    if lines[0] == "```":
                        index = index + 1

                    # Extract information by splitting each line on the colon
                    ip = lines[index].split(': ')[1]
                    service = lines[index + 1].split(': ')[1]
                    version_number = lines[index + 2].split(': ')[1]
                    port_number = lines[index + 3].split(': ')[1]

                    # Output the variables
                    # print("IP:", ip)
                    # print("Service:", service)
                    # print("Version Number:", version_number)
                    # print("Port Number:", port_number)

                    # service_to_lookup = "%%ftp%"
                    # version_to_lookup = "%%vsftpd 2.3.4%"
                    # service_to_lookup = "vsftpd"
                    # version_to_lookup = "vsftpd 2.3.4"

                    # Preparing SQL query to fetch data
                    print("Start SQL database search")
                    service_to_lookup = "%" + service.strip().lower() + "%"
                    print("service_to_lookup: " + service_to_lookup)
                    # version_to_lookup = "%" + version_number.strip() + "%"
                    # print("version_to_lookup: " + version_to_lookup)
                    
                    query = """
                    SELECT module_name
                    FROM modules
                    WHERE service LIKE %s;
                    """

                    # Executing the SQL command
                    cursor.execute(query, (service_to_lookup,))

                    # Fetching all records
                    results = cursor.fetchall()

                    if results:
                        print(f"Found {len(results)} results from database")

                        # set flag for success execuation
                        success = False

                        print("Start enumerating all related modules from Database")
                        # Enumerate all results 
                        for result in results:
                            print("Related Module:", result)
                            command = "use " + result[0]

                            print(f"--- Interaction {count_interaction} ---")

                            print(f"Command after finding realted module from Database: \n{command}")

                            print("\n>>>>> Enter the output from the executed command:")
                            last_output = capture_multiline_input()
                            
                            print("\n>>>>> Enter the last action (leave blank to use the generated command):")
                            last_action_input = capture_multiline_input()
                            last_action = last_action_input if last_action_input else command

                            # Process the next step
                            print("\n[INFO] Processing next action...\n")
                            result = main_chain({"IP": IP, "last_action": last_action, "last_output": last_output, "previous_tactic": tactic})
                            count_interaction += 1

                            # Update variables
                            last_output_summary = result["last_output_summary"]
                            tactic = result["tactic"]
                            command = result["command"]

                            # Print output to console
                            print(f"Tactic: {tactic}")
                            print(f"Last Output Summary:\n{last_output_summary}\n")
                            print(f"Result from the executable_output_chain: \n{command}\n")

                            log_file.write("Start enumerating all related modules from SQL")
                            log_file.write(f"--- Interaction {count_interaction} ---\n")
                            log_file.write(f"\nLast Output:\n{last_output}\n")
                            log_file.write(f"\nLast Output Summary:\n{last_output_summary}\n")
                            log_file.write(f"\nTactic: {tactic}\n")
                            log_file.write(f"\nCommand from the chain:\n{command_before_sql}\n\n")

                            # check if the module from SQL success
                            if last_output_summary.startswith("SUCCESS"):
                                print("Module from database success, stop trying other modules from database")
                                success = True
                                break

                        if not success:
                            print("Tried all modules from database and non of them success")
                        
                    else:
                        print("No data found from SQL data restrival, use the old command.")

                    # Set the sql flag
                    check_with_sql = True

                # Log the results
                log_file.write(f"--- Interaction {count_interaction} ---\n")
                log_file.write(f"\nLast Output:\n{last_output}\n")
                log_file.write(f"\nLast Output Summary:\n{last_output_summary}\n")
                log_file.write(f"\nTactic: {tactic}\n")
                log_file.write(f"\nCommand from the chain:\n{command_before_sql}\n\n")

                log_file.write(f"\nCommand after query from SQL:\n{command}\n\n")

                # Stop if the campaign ends
                if tactic == "END_OF_CAMPAIGN":
                    print("[INFO] Campaign has ended.")
                    log_file.write("===== END_OF_CAMPAIGN =====\n")
                    break

    except mysql.connector.Error as err:
        print(f"Error: {err}")

    finally:
        # Close the connection
        if 'connection' in locals() and connection.is_connected():
            connection.close()
            print("Connection closed")


if __name__ == "__main__":
    main()
