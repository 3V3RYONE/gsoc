---
layout: post
title: Summer of Code with Metasploit
subtitle: Getting Started with the GSoC Journey
cover-img: /assets/img/coverSecondPost.jpeg
share-img: /assets/img/coverSecondPost.jpeg
thumbnail-img: /assets/img/metasploit_logo.png
tags: [GSoC, Metasploit, Community]
---
  
This article summarizes my work done for making it into Google Summer of Code. It depicts my perspective on how should a candidate start working in order to successfully get selected in the GSoC program.  
  
Hey everyone, I'm Beleswar Prasad Padhi. I'm happy to share that I will be working as a GSoC Contributor for **Metasploit** organization this summer. My project proposes to implement the **HTTP-Trace** feature for Metasploit Framework's login scanner modules. When enabled, the HTTP-Trace option tracks every web request made to the server by the module and its respective response. This provides the user with more verbose details, which helps them in better analyzing any errors that may occur when running the module. Here is the link to my project in the GSoC site : [Project](https://summerofcode.withgoogle.com/programs/2022/projects/I4PxrljP) 
  
So let's start from scratch.  
  
## What is GSoC?  
Google Summer of Code, often abbreviated as GSoC, is a program administered by Google that encourages budding developers from all around the globe to contribute to Open Source projects. During GSoC, selected student contributors work with an Open Source organization on a specific project for a duration of 3 months. Google certifies this work and provides a stipend to the students upon successful completion of the project! The motive of this program is to bring more developers to contribute to Open Source projects to help shape the future of software!  
  
Sounds exciting right? Let's see through the steps one by one on how to achieve it.  
  
### 1. GSoC Timeline
Understanding the timeline of the program is very essential in planning your whole work before applying for GSoC.  
- March 1-7 : List of Accepted organizations announced. During the first week of March, the accepted Open Source organizations are listed, and the organizations publish their GSoC project ideas.  
  
- April 4-19 : Contributor Application Period. During the first week of April, the contributors are required to submit their proposal stating the implementation of the projects listed earlier for an organization. This is the time when the Contributor officially needs to apply for GSoC.    
  
So, the March-April month can be utilized for selecting the project of your choice and writing the proposal. Note, writing a good proposal and having prior contributions in the organization are the most important factors in one's GSoC selection. So it's important that one dedicate time for building a strong proposal. Thus, one should start contributing to the organization in the time period before March and dedicate the following March-April month for coming up with a strong proposal for the project!
  
I personally started from January and contributed to the **Metasploit Framework** by fixing small bugs and implementing suggested features in their codebase. I became an active member in the community and frequently discussed optimal solutions for fixing bugs with the organization admins. This helped me in understanding the architecture of the framework and made my proposal stand out better, because I could demonstrate where exactly the code needs to be written for implementing my GSoC Project.  
  
### 2. Selecting your organization  
Now that we know the timeline of the Program, selecting the organization to work on is equally important. Remember, you have to work with the organization for 3 months. So, choose the organization which you are really passionate about. GSoC brings plenty of organizations with projects from every field like Security, AI, Cloud, Web, Kernel etc. Go through the GSoC archive and select a few organizations which are regularly participating in the program and have project ideas suiting your interest. Reach out to the organization community through their IRC channels or Slack and talk with them about contributing. Finding a good welcoming community is also essential as they will guide you throughout the project.  
  
I personally went with Metasploit because I really liked the community. They were welcoming and guided me whenever I got stuck while working on a bug. Apart from that, I am really passionate about Cybersecurity and have used the Metasploit Framework quite often for penetration testing. I have always wanted to contribute to a tool/project which I use frequently, thus I went forward with Metasploit!  
  
### 3. Start Early  
Starting early always helps you to achieve any task smoothly. So once we have selected the organization, one should start contributing to their codebase early. Creating the first pull request is very difficult, but creating the upcoming ones is easier. We can always approach the community for any guidance if we are stuck at a point while fixing a bug. Thus, it's always about when you start. If you start early, you have a thorough understanding of the architecture of the organization that helps in making your proposal stronger. Prior contributions carries a good impression on one's application and allows one to formulate a better approach to the main GSoC project.  
  
As stated earlier, I started contributing to Metasploit since the month of January. So, I spent three months contributing to the codebase where I created 5 pull requests, reviewed 2 pull requests, raised 1 issue and answered/resolved on 2 issues reported. My contributions to the framework have ranged from fixing database issues, updating libraries, adding commands to the Meterpreter and up to writing a new login scanner module [wip]!  
  
### 4. Proposal  
Submitting a strong proposal is the final and the most important step in one's selection for GSoC. A good proposal should be able to convince the organization that you are capable of implementing the project. The proposal must describe the **Methodology** section in a detailed manner, where you describe which parts of the code should be modified and what modules need to be added etc. to implement the project. One can also showcase their past contributions here and a detailed section about their skills which will strengthen the proposal. The proposal should also talk about your weekly commitments for the project. Finally, make sure to divide the project into small weekly tasks and propose what you would be achieving after every week in the **Timeline** section of the proposal.  
  
I spent the whole month (March-April) in understanding the project in detail and drafting the proposal. I went through the codebase in the first week and came up with a solution to implement the project. Following which, I drafted a rough proposal consisting of the sections : **Objective, Methodology, About Me and Skills** in the second week of the month. I requested the organization mentors for a review on my draft proposal and followed up on their suggestions. This took time but helped me develop a great proposal. Thus, **having your proposal reviewed by organization members is an essential step in developing a strong proposal**, as they can point out to any points which the proposal might be missing.  
  
You can take a look at my proposal for GSoC'22 @Metasploit here : [https://summerofcode.withgoogle.com/media/user/5c91a6709fda/proposal/VeBNITd7xftLinOR.pdf](https://summerofcode.withgoogle.com/media/user/5c91a6709fda/proposal/VeBNITd7xftLinOR.pdf)
  
### Conclusion  
GSoC program is indeed a great learning experience, and I am thriving to obtain the best out of it! With this, I wish all my fellow GSoC contributors a great summer experience and I hope some of these tips help future GSoCers! :)
