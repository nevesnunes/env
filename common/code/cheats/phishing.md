# case studies

- https://mrd0x.com/browser-in-the-browser-phishing-attack/
    ```javascript
    // <a href="https://gmail.com" onclick="return launchWindow();">Google</a>
    function launchWindow(){
        // Launch the fake authentication window
        return false; // This will make sure the href attribute is ignored
    }
    ```
- https://twitter.com/LiveOverflow/status/1289243231100772353
    > my brother renamed himself to "Zoom" in a zoom call with his teacher and requested access to the teacher's computer. The teacher saw "Zoom is requesting access to your computer" and clicked Allow
- https://twitter.com/secalert/status/1289245645836939265
    > Reminds me of the case when @kevinmitnick registered a company named "Trusted Vendor" so that when his malicious Java Applet asks for permission or shows the certificate it would say "Publisher: trusted vendor" and the victim would trust it.
- https://twitter.com/kl_sree/status/1289251679917895681
    > There was a guy live streaming in YouTube with his Gmail notifications enabled. Eventually somebody sent password reset email and got the verification code through the video.
