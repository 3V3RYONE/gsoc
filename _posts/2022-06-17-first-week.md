---
layout: post
title: GSoC Week 1
subtitle: Analyzing Library Code
cover-img: /assets/img/coverSecondPost.jpeg
share-img: /assets/img/coverSecondPost.jpeg
thumbnail-img: /assets/img/thirdPostThumbnail.png
tags: [GSoC, Metasploit, Coding]
---
  
The Coding Period is finally here! This article summarizes the work done during the first week of the Coding Period of Google Summer of Code. The primary work during the first week was to analyze the related library code and figure out where exactly new code needs to be implemented!  
  
As mentioned in my last blog post, [read it here](https://3v3ryone.github.io/gsoc/2022-06-08-community-bonding-period/), we worked out some changes in the plan of project during the community bonding period. Thus, it was worth our time to spend the first week in analyzing the existing library code, so that we know the method calls and where exactly the HTTP-Trace wrapper class needs to be present, what parameters are needed to be passed to the method in wrapper class etc. Let's continue and look at the work done in details. Here is the link to my project in the GSoC site : [Project](https://summerofcode.withgoogle.com/programs/2022/projects/I4PxrljP)  
  
The week's work was divided into three tasks primarily. All of the tasks had specific work and combining results from all of them gave a clear view of the path of code in the next weeks.  
  
## Task 1 : Analyzing Library Code  
  
There are particularly three library files of interest with respect to this project: **Exploit::Remote::HttpClient**, **Rex::Proto::Http::Client** and **Rex::Proto::Http::Server**.  
  
## Task 2 : Understanding Flow of Control of Methods  
  
The library code had various methods sending requests and obtaining responses to an HTTP server. But, All of the methods have something unique in the way they craft the request and the work they perform upon the received responses. For example, **send_request_raw()**, **send_request_cgi()** and **send_request_cgi!()** are three methods of the **Exploit::Remote::Http::Client** Class which essentially send HTTP requests to the designated URI but perform a specific task with their Response. So, the question was "Do we need to make a function call to HTTP-Trace in each of these methods? Wouldn't it be inefficient with so many function calls?".  
  
Thus, understanding the flow of control and figuring out the single optimal method where the HTTP-Tracing needs to be implemented was a great challenge.  
  
The following describes every method of interest and explains their flow:  
* **send_request_raw()**  
* **send_request_cgi()**
* **send_request_cgi!()**
* **request_raw()**
* **request_cgi()**
* **send_recv()**
* **send_recv()**  
  
Thus, it ultimately comes out to the `_send_recv()` method where the HTTP-Tracing needs to be implemented! All the methods which craft their own requests directly or indirectly call the `_send_recv()` method for sending the request to the server and obtaining the response back!

## Task 3 : Objects and Parameters  
  
## Conclusion  
  
This marks the end of the Community Bonding Period of GSoC'22 :)! The Community Bonding period was really exciting and informative, where I got to know about the real-life workflow in an Organization and how to plan the timeline of the project effectively. This included Project Management, Official meetings and of course, clear communication with my Mentor. I really appreciate the essence of this period specifically dedicated to the contributors in getting acquainted to the Organization and learning about their workflow!  
  
Catch you up in the coding period! :)
