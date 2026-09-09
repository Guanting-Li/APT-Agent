# Define the path to your input file
input_file_path = 'module_names.txt'
# Define the path to your output file
output_file_path = 'modified_module_names.txt'

# Open the input file and process each line
with open(input_file_path, 'r') as infile, open(output_file_path, 'w') as outfile:
    for line in infile:
        # Split the line into parts, assuming the index is the first part and is separated by a space
        parts = line.split(' ', 1)

        # Check if there is a second part to process
        if len(parts) > 1:
            # Remove the index and replace all '/' with ' '
            modified_line = parts[1].replace('/', ' ').strip()

            # Write the modified data to the output file, adding a newline character
            outfile.write(modified_line + '\n')

# Inform the user that the file has been processed
print("The modules have been processed and saved to 'modified_modules.txt'.")
