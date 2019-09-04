#!/usr/bin/python

import socket		# for sokets
import sys			# for exit
import select		# for select
import struct		# for struct.pack()
from proxy_server_utils import *


FTP20_PROXY_HOST_IN = '10.0.2.3'
FTP20_PROXY_PORT_IN = 8009
MAX_PACKET_SIZE = 4096


def main():

	try:
		s_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error, msg:
		print 'Failed to create IN socket. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	print 'IN Socket created'

	try:
		s_in.bind((FTP20_PROXY_HOST_IN, FTP20_PROXY_PORT_IN))
		#s_in.bind(('10.0.2.3', 8009))
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
		print '++++++++++++++++++++++++++++'
		while conn_active:
			#print 'PROXY - before select'
			readable, writable, exceptional = select.select(inputs, outputs, inputs)
			#print 'PROXY - after select'
			for s in readable:
				if s == conn_in:
					#print 'PROXY - s_in'
					frame = conn_in.recv(MAX_PACKET_SIZE)
					if frame:
						#print 'PROXY - s_in 0'
						#print frame
						bin_frame = bytearray(frame)
						#1A 45 DF A3 - magic number of mkv files
						if bin_frame[0] == 49 and bin_frame[1] == 65 and bin_frame[2] == 32 and \
						bin_frame[3] == 52 and bin_frame[4] == 53 and bin_frame[5] == 32 and \
						bin_frame[6] == 68 and bin_frame[4] == 70 and bin_frame[5] == 32 and \
						bin_frame[6] == 65 and bin_frame[4] == 51:
							#send the ip and port for the fw to close the connection in connection table
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
							s_out.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
							conn_in.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
							#conn_in.shutdown(socket.SHUT_RDWR)
							conn_active = 0
							readable.remove(conn_in)
							signal_ftp21()
							print 'PROXY - blocked .mkv file'
							continue
						#MZ - exe file magic number
						if bin_frame[0] == 77 and bin_frame[1] == 90:
							#send the ip and port for the fw to close the connection in connection table
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
							s_out.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
							conn_in.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
							#conn_in.shutdown(socket.SHUT_RDWR)
							conn_active = 0
							readable.remove(conn_in)
							signal_ftp21()
							print 'PROXY - blocked .exe file'
							continue
						#print 'PROXY - s_in 4'
						s_out.sendall(frame)
						readable.remove(conn_in)
					else:
						#print 'PROXY - s_in 5'
						readable.remove(conn_in)
						#conn_in.shutdown(socket.SHUT_RD)
						conn_active = 0
						continue
				if s == s_out:
					#print 'PROXY - s_out'
					frame = s_out.recv(MAX_PACKET_SIZE)
					if frame:
						#print 'PROXY - s_out 1'
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
