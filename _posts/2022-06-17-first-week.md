---
layout: post
title: GSoC Coding Period - Week 1
subtitle: Analyzing related Library Code
cover-img: /assets/img/coverSecondPost.jpeg
share-img: /assets/img/coverSecondPost.jpeg
thumbnail-img: /assets/img/thirdPostThumbnail.png
tags: [GSoC, Metasploit, Coding]
---
  
The Coding Period is finally here! This article summarizes the work done during the first week of the Coding Period of Google Summer of Code. The primary work during the first week was to analyze the related library code and figure out where exactly new code needs to be implemented!  
  
As mentioned in my [last blog post](https://3v3ryone.github.io/gsoc/2022-06-08-community-bonding-period/), we worked out some changes in the plan of project during the community bonding period. Thus, it was worth my time to spend the first week analyzing the existing library code, so that I know the method calls and where exactly the HTTP-Trace wrapper class needs to be present, what parameters need to be passed to the method in wrapper class etc. Let's continue and look at the work done in details. Here is the link to my project in the GSoC site : [Project](https://summerofcode.withgoogle.com/programs/2022/projects/I4PxrljP)  
  
The week's work was divided into three tasks primarily. All the tasks were performed separately, however combining the results from all of them gave a clear view of the path to proceed with the project.  
  
## Task 1 : Analyzing Library Code  
  
There are four library files of interest with respect to this project: [Rex::Proto::Http::Client](https://github.com/rapid7/metasploit-framework/blob/98b2234cab8cbb60f6907a268f65e69de7b7aae7/lib/rex/proto/http/client.rb), [Rex::Proto::Http::Server](https://github.com/rapid7/metasploit-framework/blob/98b2234cab8cbb60f6907a268f65e69de7b7aae7/lib/rex/proto/http/server.rb), [Exploit::Remote::HttpClient](https://github.com/rapid7/metasploit-framework/blob/98b2234cab8cbb60f6907a268f65e69de7b7aae7/lib/msf/core/exploit/remote/http_client.rb) and [Exploit::Remote::HttpServer](https://github.com/rapid7/metasploit-framework/blob/98b2234cab8cbb60f6907a268f65e69de7b7aae7/lib/msf/core/exploit/remote/http_server.rb). The Rex class is a central class which provides connection and configuration services for the HTTP Client (through Rex::Proto::Http::Client) and the HTTP Server (through Rex::Proto::Http::Server) to all the modules in the framework (like Auxiliary, Exploits, Encoders, Payloads etc). On the other hand, the Exploit class provides HTTP Client services (through Exploit::Remote::HttpClient) and HTTP Server services (through Exploit::Remote::HttpServer) only to the _exploit modules_ which import their functionality.  
  
In the process of researching through the codebase, I found that the Exploit::Remote::HttpClient is reliant on the Rex::Proto::Http::Client for making requests to the server and obtaining back the responses. In the same way, Exploit::Remote::HttpServer is reliant on the Rex::Proto::Http::Server class for sending responses back to the Client. Thus, the Exploit class does not transmit requests on its own, rather it makes a call to the methods of Rex class for doing so. Thus, our plan of creating the HTTP-Trace wrapper class for Rex::Proto::Http::Client and Rex::Proto::Http::Server will also serve the Exploit::Remote::Http::Client and Exploit::Remote::Http::Server with HTTP-Trace features since the later are reliant on the former.  
  
| ![codeExampleClientDependency](../assets/img/clientReliant.png) |  
| Figure 1: Code Example showing that _send_request_raw()_ method in [Exploit::Remote::HttpClient](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/http_client.rb#L378) is reliant on _send_recv()_ method in [Rex::Proto::Http::Client](https://github.com/rapid7/metasploit-framework/blob/98b2234cab8cbb60f6907a268f65e69de7b7aae7/lib/rex/proto/http/client.rb#L209-L215) |
  
<br/>
  
| ![codeExampleServerDependency](../assets/img/serverReliant.png) |  
| Figure 2: Code example showing that _send_response()_ method in [Exploit::Remote::HttpServer](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/http_server.rb#L582) is reliant on _send_response()_ method in [Rex::Proto::Http::Server](https://github.com/rapid7/metasploit-framework/blob/98b2234cab8cbb60f6907a268f65e69de7b7aae7/lib/rex/proto/http/server.rb#L35-L45) |  
  
While analyzing the Client files, i.e. Rex::Proto::Http::Client and Exploit::Remote::HttpClient, it was noted that the HTTP Client sends different types of requests (e.g. requests crafted with specific cookies, or requests crafted to follow redirect to the location obtained in response etc.) to the server and grabs the response. For a pentester, looking at the details of both the request and response might be necessary. For example, consider the scenario when we are running a brute force module to attempt login on an authentication page. We might be interested in seeing the pair of HTTP request and response for every credential being tried. As module writers, we need to ensure the credentials used for every request gets updated. We also need to check the location in the response to ensure that the login page has redirected incase of a successful credential attempt. Thus, it is essential to track both requests and responses on the client side through HTTP-Trace.  
  
On the other hand, analyzing the Server files, i.e. Rex::Proto::Http::Server and Exploit::Remote::HttpServer, showed that the HTTP Server accepts the request sent from the client, reads its data and tries to allocate the resource requested. Depending on if the resource allocation was successful or not, the server sends different types of responses (e.g. 404 error response, 302 redirect response etc.) to the client through its __send_response()__ method. For a developer working upon errors at the server side, it might be necessary to view client requests, to understand why the HTTP server is not parsing the request correctly. Also, the status returned by the server might be necessary to understand how the resource was allocated to the request. Thus, it is also essential to track both requests and responses on the server side through HTTP-Trace.  
  
Thus, results of the analysis proved that a wrapper class can be successfully created at Rex::Proto::Http location which can be imported into the above listed libraries. The analysis also found out the necessary register options and parameters needed for the HTTP-Trace method, which are listed in the [TASK 3](https://3v3ryone.github.io/gsoc/2022-06-17-first-week/#task-3-:-objects-and-parameters) section.   
  
## Task 2 : Understanding Flow of Control of Methods  
  
The Server library code is simple because, we have just one method `on_client_data()` which reads the HTTP request obtained, and one method `send_response()` which sends the HTTP response to the client. Thus, we can implement HTTP-Trace in the `on_client_data()` and `send_response()` methods by making a call to the HTTP-Trace wrapper class in these locations.  
  
However, the Client library code had various methods sending requests and obtaining responses to an HTTP server. All the methods have something unique in the way they craft the request and the work they perform upon the received responses. For example, **send_request_raw()**, **send_request_cgi()** and **send_request_cgi!()** are three methods of the **Exploit::Remote::Http::Client** Class which essentially send HTTP requests to the designated URI but perform a specific task with their Response. So, the question was, "Do we need to make a function call to HTTP-Trace in each of these methods? Wouldn't it be inefficient with so many function calls?".  
  
Thus, understanding the flow of control and figuring out the single optimal method where the HTTP-Tracing needs to be implemented was a great challenge.  
  
The following describes every method of interest and explains their flow:  
  
1. **send_request_raw()**: This method in Exploit::Remote::HttpClient, simply connects to the HTTP server, creates a request, sends the request, and reads the response. It lays the base for carrying out more specific functionalities on top of it. Currently, the HTTP-Trace functionality is implemented in this method. This method makes a call to the **send_recv()** method of the Rex::Proto::Http::Client class, for sending the Request and getting the Response. (see Figure 1)
(**send_recv()** method further forwards the request to `_send_recv()` method, where the request gets transmitted. See Point 4.)  
  
2. **send_request_cgi()**: This method in Exploit::Remote::HttpClient, is dedicated to pass a special instance of cookie in the headers of the request. This method then makes a call to the **send_request_raw()** method discussed above, to carry out the basic functionality. (Call stack = **send_request_cgi()** -> **send_request_raw()** -> **send_recv()** -> `_send_recv()`. See Point 1.)  
  
3. **send_request_cgi!()**: This method in Exploit::Remote::HttpClient, performs the basic functionalities like connecting to the server, creating a request with the **COOKIE** header, sending the request etc. Along with that, tt also reads the response, if a redirect (HTTP 30x response) is received, it will attempt to follow the redirect and retrieve that URI. This method makes a call to the **send_request_cgi()** method discussed above, to carry out the basic functionality. (Call stack = **send_request_cgi!()** -> **send_request_cgi()** -> **send_request_raw()** -> **send_recv()** -> `_send_recv()`. See Point 2.) 
  
4. **send_recv()**: This method in the Rex::Proto::Http::Client class, sends a request and gets a response back. If the response received is a 401, it attempts to authenticate to that URI with the username/password credentials and returns the final response back. This method makes a call to the `_send_recv()` method for sending the request and obtaining the response back. [Link to code example](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb#L209-L210)  
  
5. `_send_recv()`: As the name suggests (send and receive), this method is solely responsible for transmitting the HTTP request and receiving the response back. It does not call any other method, and all the code for transmitting the request to the server is implemented here. Thus, this method is the central location for handling all requests and responses, and all the methods essentially make a **call** here, for transmitting requests!  
  
| ![flowchart](../assets/img/flowchart.png) |  
| Figure 3: An infographic showing the Flow of Control of methods |    
  
The call stack of methods and flow chart shown above depict that `_send_recv()` method is the bottleneck gateway to transmit all requests to the server. All the methods which craft their own requests, directly or indirectly **call** the `_send_recv()` method for sending the request to the server and obtaining the response back! Thus, it ultimately comes out to the `_send_recv()` method in Rex::Proto::Http::Client where the HTTP-Tracing needs to be implemented (We can make a function call to the HTTP-Trace wrapper class at this point).  
  
[task3AnchorLink](#task-3-:-objects-and-parameters)  
  
## Task 3 : Objects and Parameters  
  
Now that we know where we have to make the function call for HTTP-Trace, we have to determine what objects and parameters are needed to be passed to the function, for effective tracking of HTTP requests and responses. After analyzing the library code, I believe it is sufficient to pass the following parameters for effective tracking:  
  
1. **request object**: The request object containing all information like URI, Port, SSL, Headers, Method, Connection, Cookie etc. For client side, we could call the HTTP-Trace method with this request object as parameter, just after the request is ready to be transmitted to the HTTP server. For server side, we could call the HTTP-Trace method with this request object as parameter, just after the request is ready to be parsed.  
  
2. **response object**:  The response object containing all information like Response code, Server, Location, Content-Type etc. For client side, we could call the HTTP-Trace method with this response object as parameter, just after we have received the response from the HTTP server. For server side, we could call the HTTP-Trace method with this response object as parameter, just before the response is sent to the HTTP client.  
  
3. **colors**:  A pair of colors can be passed as parameter as well, along with requests and responses. This will help to distinguish the requests and responses when they are printed into the msfconsole with unique colors each. So, we could pass the colors parameter in the style `color1/color2` for requests and responses, respectively.  
  
  
| ![sampleMethodCallImage](../assets/img/sampleCallMethod.png) |  
| <b> Figure 4: Image showing a sample method call to HTTP-Trace method with parameters from the `_send_recv()` method for HTTP Client </b>|  
  
<br/>  
  
| ![sampleMethodCallImage](../assets/img/sampleCallMethodServer.png) |  
| <b> Figure 5: Image showing a sample method call to HTTP-Trace method with parameters from the `send_response()` method for HTTP Server </b>|  
  
## Conclusion  
  
It's a wrap for Week 1 :) The research work in this week was very informative, which clarified the location and parameters of the function call to HTTP-Trace method. Thus, our next plan in Week 2 is to actually create the wrapper class in Rex::Proto::Http library and define the HTTP-Trace method with the above parameters.  
  
Catch you up in the second week! :)
