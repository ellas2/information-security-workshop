#!/usr/bin/python

from collections import Counter


'''
connection.shutdown(FLAG)
	FLAG = SHUT_RD - further receives are disallowed. 
	FLAG = SHUT_WR - further sends are disallowed. 
	FLAG = SHUT_RDWR - further sends and receives are disallowed
'''
def check_if_C_code(frame):
	
	#c_dict = ['auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'inline', 'int', 'long', 'register', 'restrict', 'return', 'short', 'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while', '&&', '||', '!=' '==', '->', 'NULL', ');', '];', "';"]
	# source: http://en.cppreference.com/w/c/keyword
	
	c_dict1 = ['char', 'const', 'enum', 'float', 'goto', 'int', 'sizeof', 'struct', 'typedef', 'NULL', '#ifdef', '#endif', 'size_t']
	c_dict2 = ['#include', '#define', 'strlen', 'printf', 'strcmp', 'strcat', 'scanf', 'malloc', 'calloc', 'while(', 'for(', 'if(', 'else{', 'do{', 'brack;', ']=', 'argc', 'argv', 'close(', 'open(', 'write(', 'read(', 'while (', 'for (', 'if (', 'else {', 'do {', 'brack;', '] =', '[]', '__', '};', ');', '){', ') {', 'return 0', 'return -1', 'return 1', 'void main(', 'void main (', 'int main(', 'int main (', 'close (', 'open (', 'write (', 'read (', 'unsigned short', 'unsigned double', 'unsigned long', 'unsigned float',  '&&', '||', '!=', '==', '->', ');', '];', "';", '%d', '%s', '%c', '%l']
	
	if len(frame) < 60:
		return False
	
	wordcount = Counter(frame.split())
	count1 = 0
	count2 = 0
	for item in wordcount.items():
		if item[0] in c_dict1:
			count1 += item[1]
	
	for item in c_dict2:
		count2 += frame.count(item)

	ratio = ((count1+count2)*100)/len(wordcount)
	if ratio >= 30:
		return True
	
	return False
	

def IP2Int(ip):
	# source: https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
	o = map(int, ip.split('.'))
	res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
	return res

def Int2IP(ipnum):
	# source: https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
	o1 = int(ipnum / 16777216) % 256
	o2 = int(ipnum / 65536) % 256
	o3 = int(ipnum / 256) % 256
	o4 = int(ipnum) % 256
	return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

def get_dst_host_ip(ip, port):
	try:
		f = open("/sys/class/fw/conn_tab/proxy", "r+")
	except f.error, msg:
		print 'Failed to open sysfs device. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	ip_int = IP2Int(ip)
	#buf = '' + 'A ' + str(ip_int) + ' ' + str(port)
	buf = str(ip_int) + ' ' + str(port)
	print buf
	f.write(buf)		
	f.seek(0)
	buf = '' + f.read()
	print buf
	ip_int, port = buf.split()
	ip_str = Int2IP(int(ip_int))
	f.close()
	return (ip_str, port)
	
def open_ftp2021():
	try:
		f = open("./signal.txt", "w+")
	except f.error, msg:
		sys.exit()
	buf = '0'
	f.write(buf)
	f.close()
			
def signal_ftp21():
	try:
		f = open("./signal.txt", "w+")
	except f.error, msg:
		sys.exit()
	buf = '1'
	f.write(buf)
	f.close()
			
def check_ftp20():
	try:
		f = open("./signal.txt", "r")
	except f.error, msg:
		sys.exit()
	buf = '' + f.read()
	f.close()
	if buf == '1':
		return 1
	else:
		return 0

def close_connection_in_fw(buf):
	try:
		f = open("/sys/class/fw/conn_tab/conns", "r+")
	except f.error, msg:
		print 'Failed to open sysfs device. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	f.write(buf)
	f.close()
							
