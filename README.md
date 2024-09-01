# copenheimer-masscan
-This exploits a vulnerability in Minecraft allowing the user to find any player on any server worldwide.

![image](https://cdn.discordapp.com/attachments/1185258518153011343/1278466248400699482/Screenshot_2024-08-28_162745.png?ex=66d0e7fa&is=66cf967a&hm=fd7393d186cfbf85d3b6ab86874bda73b35e68211fc532e82dd8bba863695876&)

**Build instructions:**
- Install build tools in Linux if needed
- cmake CMakeLists.txt
- make

**Example command using minecraft banner check:**
- sudo ./masscan (Misc args) --banners --hello=minecraft --source-ip 192.168.1.234 (192.168.1.234 is just an example ip, for production replace with an unused LAN ip)
**Featured in**
Featured in - https://www.youtube.com/watch?v=fvbVnT-RW-U and https://www.youtube.com/watch?v=hoS0PM20KJk
note: do not use this to grief innocent players, its simply for educational purposes
  
- iptables -A INPUT -p tcp --dport 61000 -j DROP
- sudo ./masscan (Misc args) --banners --hello=minecraft --source-port 61000

**Credits**
- The original masscan developer(robertdavidgraham)
- Orsondmc and 0x22 for contributions.  

**Disclaimer** 
- I am not responsible for any way you choose to use this project. Remember port scanning can lead to dangerous consequences and not all organizations will appreciate being port-scanned. There is an exclude config file added to exclude certain ip ranges.


