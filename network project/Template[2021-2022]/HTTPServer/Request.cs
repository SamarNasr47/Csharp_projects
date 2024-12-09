using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPServer
{
    public enum RequestMethod
    {
        GET
    }

    public enum HTTPVersion
    {
        HTTP10,
        HTTP11,
        HTTP09
    }

    class Request
    {
        string[] requestLines;
        RequestMethod method;
        public string relativeURI;
        Dictionary<string, string> headerLines = new Dictionary<string, string>();

        public Dictionary<string, string> HeaderLines
        {
            get { return headerLines; }
        }

         HTTPVersion httpVersion;
        string requestString;
        string[] requestlayer;

        public Request(string requestString)
        {
            this.requestString = requestString;
        }
        /// <summary>
        /// Parses the request string and loads the request line, header lines and content, returns false if there is a parsing error

        /// </summary>  
        /// <returns>True if parsing succeeds, false otherwise.</returns>

        public bool ParseRequest()
        {   //TODO: parse the receivedRequest using the \r\n delimeter  
           // throw new NotImplementedException();
            bool result;

            string[] s = { "\r\n" };
            requestlayer = requestString.Split(s, StringSplitOptions.None);
            // check that there is atleast 3 lines: Request line, Host Header, Blank line (usually 4 lines with the last empty line for empty content)
            if (requestlayer.Length < 3)
            {
                return false;
            }
            // Parse Request line
            requestLines = requestlayer[0].Split(' ');
            bool r = ParseRequestLine();
            // Validate blank line exists
            bool b = ValidateBlankLine();

            // Load header lines into HeaderLines dictionary
            bool h = LoadHeaderLines();
            if (r && b && h == true)
            {
                result = true;
            }
            else
            { result = false; }

            return result;
        }

        private bool ParseRequestLine()
        {
            //throw new NotImplementedException();
            if (requestLines.Length < 3)
            {
                return false;
            }
            else
            {
                method = RequestMethod.GET;
                switch (requestLines[2])
                {
                    case "HTTP/1.1":
                        httpVersion = HTTPVersion.HTTP11;
                        break;
                    case "HTTP/1.0":
                        httpVersion = HTTPVersion.HTTP10;
                        break;
                    case "HTTP/0.9":
                        httpVersion = HTTPVersion.HTTP09;
                        break;
                }
                relativeURI = requestLines[1];
                ValidateIsURI(relativeURI);
                return true;
            }
        }
        private bool ValidateIsURI(string uri)
        {
            return Uri.IsWellFormedUriString(uri, UriKind.RelativeOrAbsolute);
        }

        private bool LoadHeaderLines()
        {
            bool a = true;
            //throw new NotImplementedException();
            for (int i = 1; i < requestlayer.Length - 2; i++)
            {
                if (requestlayer[i].Contains(":"))
                {
                    string[] H = new string[] { ": " };
                    string[] head = requestlayer[i].Split(H, StringSplitOptions.None);
                    headerLines.Add(head[0], head[1]);
                }
                else
                    a = false;


            }
            return a;

        }

        private bool ValidateBlankLine()
        {
            //throw new NotImplementedException();
            if (requestlayer[requestlayer.Length - 2] == "")
                return true;
            else
                return false;
        }

    }
}