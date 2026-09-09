# Define the path to your file
file_path = 'modules.txt'

# Open the file and process each line
with open(file_path, 'r') as file:
    for line in file:
        # Split the line into parts
        parts = line.split()

        # Extract the index, which is the first element
        index = parts[0]

        # Extract the module name, which spans multiple parts and ends before the date
        # Finding the first part that matches date pattern (assuming the date is always in 'YYYY-MM-DD' format)
        # and is always the fourth element in a well-structured line
        module_name = parts[1]
        # Print the cleaned data
        print(f'{index} {module_name}')

# You might need to adjust the script if the format isn't consistent, especially around the date detection.
