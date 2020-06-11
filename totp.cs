  //totp c# 
  
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Utils.Cryptography
{
    public class Totp
    {
        private readonly long unixEpochTicks = 621355968000000000L;
        private readonly long ticksToSeconds = 10000000L;

        public bool Validate(string code, string secret, ValidateOpts opts)
        {
             var window = CalculateTimeStepFromTimestamp(DateTime.UtcNow, opts.TimePeriod);
         
            var counterBytes = new byte[8];
            long counter = window + opts.Skew;

            //for (var i = counterBytes.Length - 1; i >= 0; i--)
            //{
            //    counterBytes[i] = (byte)(counter & 0xff);
            //    counter >>= 8;
            //}

            for (var i = 0; i < 8; i++)
            {
                counterBytes[7 - i] = /*counter & 0xff;*/ (byte)(counter & 0xff);
                counter = counter >> 8;
            }

            opts.Algorithm.Key = Base32.FromBase32String(secret);
            byte[] hmacComputedHash = opts.Algorithm.ComputeHash(counterBytes);

            int gcode = Truncate(hmacComputedHash, opts.Digits);
            var scode = gcode.ToString().PadLeft(opts.Digits, '0');

            return string.Equals(code, scode);
        }


        private long CalculateTimeStepFromTimestamp(DateTime timestamp, int step)
        {
            var unixTimestamp = (timestamp.Ticks - unixEpochTicks) / ticksToSeconds;
            long window = unixTimestamp / step;
            return window;
        }

        private int DT(byte[] hmac_result)
        {
            var offset = hmac_result[hmac_result.Length - 1] & 0xf;
            var bin_code = (hmac_result[offset] & 0x7f) << 24
               | (hmac_result[offset + 1] & 0xff) << 16
               | (hmac_result[offset + 2] & 0xff) << 8
               | (hmac_result[offset + 3] & 0xff);

            return bin_code;
        }

        private int Truncate(byte[] hmac_result, int digits)
        {
            var Snum = DT(hmac_result);
            return Snum % (int)Math.Pow(10, digits);
        }
    }

    public class ValidateOpts
    {

        public int TimePeriod { get; private set; }
        public int Skew { get; private set; }
        public int Digits { get; private set; }
        public HMAC Algorithm { get; private set; }

        public ValidateOpts()
        {
            TimePeriod = 30;
            Skew = 0;
            Digits = 6;
            Algorithm = new HMACSHA1();
        }

        public ValidateOpts(int step, int skew, int digits, HMAC algo)
        {
            TimePeriod = step;
            Skew = skew;
            Digits = digits;
            Algorithm = algo;
        }
    }
}
