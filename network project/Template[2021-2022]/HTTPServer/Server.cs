using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.IO;

namespace HTTPServer
{
    class Server
    {
        Socket serverSocket;
        IPEndPoint IPEnd;
        

        public Server(int portNumber, string redirectionMatrixPath)
        {
            //TODO: call this.LoadRedirectionRules passing redirectionMatrixPath to it
            this.LoadRedirectionRules(redirectionMatrixPath);
            //TODO: initialize this.serverSocket
            this.serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEnd = new IPEndPoint(IPAddress.Any,portNumber);
            serverSocket.Bind(IPEnd);
        }

        public void StartServer()
        {
            // TODO: Listen to connections, with large backlog.
            serverSocket.Listen(200);
            // TODO: Accept connections in while loop and start a thread for each connection on function "Handle Connection"
            while (true)
            {
                //TODO: accept connections and start thread for each accepted connection.
                Socket clientSocket = serverSocket.Accept();
                Thread newthread = new Thread(new ParameterizedThreadStart (HandleConnection));
                newthread.Start(clientSocket);

            }
        }

        public void HandleConnection(object obj)
        {
            // TODO: Create client socket 
            Socket clientSocket = (Socket)obj;
            // set client socket ReceiveTimeout = 0 to indicate an infinite time-out period
            
            // TODO: receive requests in while true until remote client closes the socket.
            while (true)
            {
                try
                {
                    // TODO: Receive request
                    byte[] receiveddata = new byte[1024*1024];
                    int recivedlenght=clientSocket.Receive(receiveddata);
                    string data = Encoding.ASCII.GetString(receiveddata);
                    Console.WriteLine(data);

                    if (recivedlenght == 0)
                    {
                        Console.WriteLine("The client ended the connection....");
                        break;
                    }
                    Request rqt = new Request(data);
                    Response rpn = HandleRequest(rqt);
                    string response = rpn.ResponseString;
                    Console.WriteLine(response);
                    byte[] fresponse= Encoding.ASCII.GetBytes(response);
                    clientSocket.Send(fresponse);

                    // TODO: break the while loop if receivedLen==0

                    // TODO: Create a Request object using received request string

                    // TODO: Call HandleRequest Method that returns the response

                    // TODO: Send Response back to client

                }
                catch (Exception ex)
                {
                    // TODO: log exception using Logger class
                    Logger.LogException(ex);
                }
            }

            // TODO: close client socket
            clientSocket.Close();
        }

        Response HandleRequest(Request request)
        {
            //throw new NotImplementedException();
            string content = "";
            Response r;
            try
            {
                //TODO: check for bad request 
                if(!request.ParseRequest())
                {
                    
                    content = LoadDefaultPage(Configuration.BadRequestDefaultPageName);
                    r = new Response(StatusCode.BadRequest, "html", content, "");
                    return r;
                }

                //TODO: map the relativeURI in request to get the physical path of the resource.
                string physPath = Configuration.RootPath + request.relativeURI;
                //TODO: check for redirect
                string xx= GetRedirectionPagePathIFExist(request.relativeURI);
                Console.WriteLine("xx:" + xx);
                if(!(xx==null||xx==""))
                {

                    
                    content = File.ReadAllText(physPath);
                    
                    r = new Response(StatusCode.Redirect,"html", content, xx);

                    Console.WriteLine("res code : "+ r.ResponseString);
                    return r;

                }
                

                //TODO: check file exists
                
                if (!File.Exists(Configuration.RootPath + request.relativeURI))
                {


                    content = LoadDefaultPage(Configuration.NotFoundDefaultPageName);
                    r = new Response(StatusCode.NotFound, "html", content, "");
                    return r;
                }
                else
                {

                    content = File.ReadAllText(Configuration.RootPath + request.relativeURI);
                   
                    r = new Response(StatusCode.Ok, "html", content, "");
                    return r;
                }
                //TODO: read the physical file

                // Create OK response 

                 
                
            }
            catch (Exception ex)
            {
                Logger.LogException(ex);

                // TODO: log exception using Logger class
                
                content =LoadDefaultPage(Configuration.InternalErrorDefaultPageName);
               
                r = new Response(StatusCode.InternalServerError, "html", content, "");
                return r;

                // TODO: in case of exception, return Internal Server Error. 
            }
        }

        private string GetRedirectionPagePathIFExist(string relativePath)
        {
            string x;
            // using Configuration.RedirectionRules return the redirected page path if exists else returns empty
            relativePath = relativePath.Substring(1);
            if(Configuration.RedirectionRules.TryGetValue(relativePath,out x))
            {
                return x;
            }
            return string.Empty;
        }

        private string LoadDefaultPage(string defaultPageName)
        {
            string filePath = Path.Combine(Configuration.RootPath, defaultPageName);
            // TODO: check if filepath not exist log exception using Logger class and return empty string
            if(!(File.Exists(filePath)))
            {
                Logger.LogException( new Exception("Not Found.."));
                return "";
            }
            else
            {
              return File.ReadAllText(filePath);
            }
            
            // else read file and return its content
            
        }

        private void LoadRedirectionRules(string filePath)
        {
            try
            {
                // TODO: using the filepath paramter read the redirection rules from file 
                string readFile = File.ReadAllText(filePath);
                // then fill Configuration.RedirectionRules dictionary 
                
                string[] split = readFile.Split(',');
                Configuration.RedirectionRules = new Dictionary<string, string>();
                Configuration.RedirectionRules.Add(split[0],split[1]);

            }
            catch (Exception ex)
            {
                // TODO: log exception using Logger class
                Logger.LogException(ex);
                Environment.Exit(1);
            }
        }
    }
}
