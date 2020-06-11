
//totp --> typescript
import base32 from 'hi-base32';
import { createHmac } from 'crypto'; //node crypto

 private generateHOTP(secret: string, counter: number) :string  {

    const len = 6;
    const buffer = Buffer.alloc(8);

    if (!secret || secret.length <= 0) {
      return this.leftpad("", len);    }    

    const decodedKey = base32.decode.asBytes(secret)
       
    for (let i = 0; i < 8; i++) {
      buffer[7 - i] = counter & 0xff;
      counter = counter >> 8;
    }

    const hmacObj = createHmac('sha1', Buffer.from(decodedKey));
    hmacObj.update(buffer);
    let hmac = hmacObj.digest();

    const hotp = this.dynamicTruncation(hmac);
    const code = hotp % (10 ** len);

    return this.leftpad(code.toString(10), len);
  }

  private dynamicTruncation(hmacVal: Buffer) {
    const offset = hmacVal[hmacVal.length - 1] & 0xf;

    return (
      ((hmacVal[offset] & 0x7f) << 24) |
      ((hmacVal[offset + 1] & 0xff) << 16) |
      ((hmacVal[offset + 2] & 0xff) << 8) |
      (hmacVal[offset + 3] & 0xff)

    );
  }

  private leftpad(str: string, len: number) : string {
    const pad = '0';
  if (len + 1 >= str.length) {
    str = Array(len + 1 - str.length).join(pad) + str;
  }
  return str;
}

  public TOTP(secret: string, window: number = 1) {
    const stepTime = 120;
    const counter = Math.floor(Date.now() / (stepTime * 1000));
    return this.generateHOTP(secret, counter+window)
  }
  
  
  

