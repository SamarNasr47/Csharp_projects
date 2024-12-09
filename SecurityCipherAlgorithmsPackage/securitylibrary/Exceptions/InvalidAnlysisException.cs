using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class InvalidAnlysisException : Exception
    {
        public InvalidAnlysisException()
        {
        }

        public InvalidAnlysisException(string message) : base(message)
        {
        }
    }
}
