#!/usr/bin/python

import socket		# for sokets
import sys			# for exit
import select		# for select
import struct		# for struct.pack()
from proxy_server_utils import *


FTP21_PROXY_HOST_IN = '10.0.1.3'
FTP21_PROXY_PORT_IN = 8008
MAX_PACKET_SIZE = 4096


def main():

	try:
		s_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error, msg:
		print 'Failed to create IN socket. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	print 'IN Socket created'
	try:
		s_in.bind((FTP21_PROXY_HOST_IN, FTP21_PROXY_PORT_IN))
		#s_in.bind(('10.0.1.3', 8008))
	except socket.error, msg:
		print 'Bind failed. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	print 'IN Socket bind complete'

	s_in.listen(10)
	print 'IN Socket now listening'

	while True:
		print '********************************************************'
		conn_in, addr = s_in.accept()
		print 'IN Socket connected with ' + addr[0] + ':' + str(addr[1])
		
		try:
			# create an AF_INET, STREAM socket (TCP)
			s_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error, msg:
			print 'Failed to create OUT socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
			s_in.close()
			sys.exit()
		print 'OUT Socket created'
		
		# Connect to remote server
		dst_host, dst_port = get_dst_host_ip(addr[0], addr[1])
		s_out.connect((dst_host , int(dst_port)))
		print 'OUT Socket connected with ' + dst_host + ':' + dst_port		
		inputs = [conn_in, s_out]
		outputs = []
		conn_active = 1
		open_ftp2021()
		print '++++++++++++++++++++++++++++'
		while conn_active:
			if check_ftp20() == 1:
				try:
					f1 = open("/sys/class/fw/conn_tab/conns", "r+")
				except f1.error, msg:
					print 'Failed to open sysfs device. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
					sys.exit()
				buf = '' + str(IP2Int(addr[0])) + ' ' + str(addr[1])
				f1.write(buf)
				f1.close()
				l_onoff = 1
				l_linger = 0
				conn_in.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
				s_out.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))	
				#s_out.shutdown(socket.SHUT_RDWR)
				conn_active = 0
				open_ftp2021()
				continue
				
			#print 'PROXY - before select'
			timeout = 1
			readable, writable, exceptional = select.select(inputs, outputs, inputs, timeout)
			#print 'PROXY - after select'
			for s in readable:
				if s == conn_in:
					#print 'PROXY - s_in'
					frame = conn_in.recv(MAX_PACKET_SIZE)
					if frame:
						#print 'PROXY - s_in 1'
						#print frame
						len_index = frame.find('PORT', 0, len(frame))
						if len_index != -1:
							#print 'PROXY - port comm'
							len_index += len('PORT ')
							count = 0
							i = 0
							first = ''
							second = ''
							while count != 6:
								if frame[len_index+i: len_index+i+1] == ' ' or frame[len_index+i: len_index+i+1] == '\r' or frame[len_index+i: len_index+i+1] == '\n':
									break
								if frame[len_index+i: len_index+i+1] == ',':
									count += 1
									i += 1
									continue
								if count == 4:
									first += frame[len_index+i: len_index+i+1]
								if count == 5:
									second += frame[len_index+i: len_index+i+1]
								i += 1
							port = int(first)*256 + int(second)
							temp = '' + first + ', ' + second + ', port= ' + str(port) 
							try:
								f1 = open("/sys/class/fw/conn_tab/proxy", "w")
							except f1.error, msg:
								print 'Failed to open sysfs device. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
								sys.exit()
							# buf = + 'B ' + src_ip + src_port + dest_ip + dest_port
							buf = '' + 'B ' + str(IP2Int(dst_host)) + ' ' + str(20) + ' ' + str(IP2Int(addr[0])) + ' ' + str(port)
							f1.write(buf)
							f1.close()

						s_out.sendall(frame)
						readable.remove(conn_in)
					else:
						#print 'PROXY - s_in 5'
						readable.remove(conn_in)
						conn_in.shutdown(socket.SHUT_RD)
						conn_active = 0
						continue
				if s == s_out:
					#print 'PROXY - s_out'
					frame = s_out.recv(MAX_PACKET_SIZE)
					if frame:
						#print 'PROXY - s_out 1'
						#print frame
						conn_in.sendall(frame)
						readable.remove(s_out)
					else:
						#print 'PROXY - s_out 2'
						readable.remove(s_out)
						s_out.shutdown(socket.SHUT_RD)
						conn_active = 0
						continue
		print 'PROXY - connection with - ' + dst_host + ':' + dst_port + ' - is done'
		s_out.close()
		#conn_in.shutdown(socket.SHUT_RDWR)
		conn_in.close()
	
						
if __name__ == "__main__":
	main()

