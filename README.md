# copenheimer-masscan

![image](https://user-images.githubusercontent.com/12180913/142133822-f4267de7-59f7-4610-b071-2ec893247cce.png)

**Build instructions:**
- Install build tools in Linux if needed
- cmake CMakeLists.txt
- make

**Example command using minecraft banner check:**
- sudo ./masscan (Misc args) --banners --hello=minecraft --source-ip 192.168.1.234 (192.168.1.234 is just an example ip, for production replace with an unused LAN ip)
  
**or:**
  
- iptables -A INPUT -p tcp --dport 61000 -j DROP
- sudo ./masscan (Misc args) --banners --hello=minecraft --source-port 61000

**Credits**
- The original masscan developer(robertdavidgraham)
- Orsondmc and 0x22 for contributions.  


