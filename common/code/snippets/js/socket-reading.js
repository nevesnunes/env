var chunk = "";
client.on('data', function(data) {
    chunk += data.toString(); // Add string on the end of the variable 'chunk'
    d_index = chunk.indexOf(';'); // Find the delimiter

    // While loop to keep going until no delimiter can be found
    while (d_index > -1) {         
        try {
            string = chunk.substring(0,d_index); // Create string up until the delimiter
            json = JSON.parse(string); // Parse the current string
            process(json); // Function that does something with the current chunk of valid json.        
        }
        chunk = chunk.substring(d_index+1); // Cuts off the processed chunk
        d_index = chunk.indexOf(';'); // Find the new delimiter
    }      
});
