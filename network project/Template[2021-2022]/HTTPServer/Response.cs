using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace HTTPServer
{

    public enum StatusCode
    {
        Ok = 200,
        InternalServerError = 500,
        NotFound = 404,
        BadRequest = 400,
        Redirect = 301


    };

    class Response
    {
        string responseString;
        public string ResponseString
        {
            get
            {
                return responseString;
            }
        }
        StatusCode code;
        List<string> headerLines = new List<string>();
        public Response(StatusCode code, string contentType, string content, string redirectoinPath)
        {

            this.code = code;
            // TODO: Add headlines (Content-Type, Content-Length,Date, [location if there is redirection])
            //throw new NotImplementedException();
            headerLines.Add(contentType);
            headerLines.Add(content.Length.ToString());
            headerLines.Add(DateTime.Now.ToString("MM/dd/yyyy hh:mm tt"));


            string status_Line = GetStatusLine(code);
            string Content_Type = "content-Type : " + headerLines[0];
            string Content_Length = "Content-Length : " + headerLines[1];
            string Date = "Date : " + headerLines[2];


            // TODO: Create the request string
            responseString = status_Line + "\r\n" + Content_Type + "\r\n" + Content_Length + "\r\n" + Date + "\r\n" + "\r\n" + content;

            if (code == StatusCode.Redirect)
            {
                headerLines.Add(redirectoinPath);

                string Location = "Location : " + headerLines[3];

                

                responseString = status_Line + "\r\n" + Content_Type + "\r\n" + Content_Length + "\r\n" + Date + "\r\n" + Location + "\r\n" + "\r\n" + content;
            }




        }

        private string GetStatusLine(StatusCode code)
        {
            // TODO: Create the response status line and return it
            string statusLine = string.Empty;

            if (code == StatusCode.Ok)
            {
                statusLine = "HTTP/1.1" + " " + ((int)code).ToString() + " " + code.ToString();

            }
            else if (code == StatusCode.BadRequest)
            {
                statusLine = "HTTP/1.1" + " " + ((int)code).ToString() + " " + code.ToString();

            }
            else if (code == StatusCode.NotFound)
            {
                statusLine = "HTTP/1.1" + " " + ((int)code).ToString() + " " + code.ToString();

            }
            else if (code == StatusCode.InternalServerError)
            {
                statusLine = "HTTP/1.1" + " " + ((int)code).ToString() + " " + code.ToString();
            }
            else if (code == StatusCode.Redirect)
            {
                statusLine = "HTTP/1.1" + " " + ((int)code).ToString() + " " + code.ToString();
            }
            return statusLine;
        }
    }
}