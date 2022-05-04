# copenheimer-masscan
-This exploits a vulnerability in Minecraft allowing the user to find any player on any server worldwide.

![image](https://user-images.githubusercontent.com/12180913/142133822-f4267de7-59f7-4610-b071-2ec893247cce.png)

**Build instructions:**
- Install build tools in Linux if needed
- cmake CMakeLists.txt
- make

**Example command using minecraft banner check:**
- `sudo ./masscan (Misc args) --banners --hello=minecraft --source-ip 192.168.1.234 (192.168.1.234` is just an example ip, for production replace with an unused LAN ip)
**Featured in**
Featured in - https://www.youtube.com/watch?v=fvbVnT-RW-U and https://www.youtube.com/watch?v=hoS0PM20KJk
**note: do not use this to grief innocent players, its simply for educational purposes**
**or:**
  
- `iptables -A INPUT -p tcp --dport 61000 -j DROP`
- `sudo ./masscan (Misc args) --banners --hello=minecraft --source-port 61000`

**Credits**
- The original masscan developer(robertdavidgraham)
- Orsondmc and 0x22 for contributions.  

**Disclaimer** 
- **I am not responsible for any way you choose to use this project. Remember port scanning can lead to dangerous consequences and not all organizations will appreciate being port-scanned. There is an exclude config file added to exclude certain ip ranges.**


