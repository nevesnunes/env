$http = [System.Net.HttpListener]::new() 
$http.Prefixes.Add("http://localhost:8080/")
$http.Start()

# Log ready message to terminal 
if ($http.IsListening) {
    write-host "HTTP Server Ready!" -f 'y'
    write-host "At: $($http.Prefixes)" -f 'y'
}

while ($http.IsListening) {
    # Get Request Url
    # When a request is made in a web browser the GetContext() method will return a request object
    # Our route examples below will use the request object properties to decide how to respond
    $context = $http.GetContext()
    if ($context.Request.HttpMethod -eq 'GET' -and $context.Request.RawUrl -eq '/') {
        # We can log the request to the terminal
        write-host "$($context.Request.UserHostAddress)  =>  $($context.Request.Url)" -f 'y'

        # the html/data you want to send to the browser
        # you could replace this with: [string]$html = Get-Content "C:\some\path\index.html" -Raw
        [string]$html = "<h1>A Powershell Webserver</h1><p>home page</p>" 
        
        #resposed to the request
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html) # convert htmtl to bytes
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length) #stream to broswer
        $context.Response.OutputStream.Close() # close the response
    } else if ($context.Request.HttpMethod -eq 'POST' -and $context.Request.RawUrl -eq '/') {
        # decode the form post
        # html form members need 'name' attributes as in the example!
        $FormContent = [System.IO.StreamReader]::new($context.Request.InputStream).ReadToEnd()

        # We can log the request to the terminal
        write-host "$($context.Request.UserHostAddress)  =>  $($context.Request.Url)"
        Write-Host $FormContent -f 'Green'

        # the html/data
        [string]$html = "<h1>A Powershell Webserver</h1><p>Post Successful!</p>" 

        #resposed to the request
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close() 
    } else if ($context.Request.HttpMethod -eq 'POST' -and $context.Request.RawUrl -eq '/stop') {
        write-host "Stopping HTTP Server..." -f 'y'
        break;
    }
}
