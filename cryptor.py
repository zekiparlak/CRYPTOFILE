from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import MD5
import os

class Main:

	def __init__(self):
		pass

	def getFilepaths(self,dirs,files):
		for dir in dirs:
			if(os.path.isdir(dir)):
				os.chdir(dir)
				self.getFilepaths(os.listdir(),files)
				os.chdir("..")
			else:
				file = os.path.abspath(dir)
				files.append(file)
		return files

	def getPassword(self,choice):
		password = str(input("Enter password:"))
		if(choice == "E"):
			f = open("../password.txt","w")
			res = MD5.new( password.encode("UTF-8"))
			f.write(str(res.digest()))
			f.close()
		else:
			try:
				f = open("../password.txt","r")
			except:
				print("Password file is missing")
				return None
			password_to_read = f.read()
			res = MD5.new(password.encode("UTF-8"))
			if(str(password_to_read) == str(res.digest())):
				return password
			else:
				print("Wrong Password")
				return None
			f.close()
			
		return password

	def getKey(self,password):
		hasher = SHA256.new(password.encode('utf-8'))
		return hasher.digest()

	def process(self,choice):
		filepaths = []
		filepaths = self.getFilepaths(os.listdir(),filepaths)
		scriptname = os.path.realpath(os.path.basename(__file__))
		if(choice == "E"):
			password = self.getPassword(choice)
			key = self.getKey(password)
			cry = Cryptor(key)
			for filename in filepaths:
				if(filename != scriptname):
					cry.encrypt_file(filename)
					print("Encrypted >",filename)
		elif(choice == "D"):
			password = self.getPassword(choice)
			if(password == None):
				return
			key = self.getKey(password)
			cry = Cryptor(key)
			for filename in filepaths:
				if(filename != scriptname):
					cry.decrypt_file(filename)
					print("Decrypted >",filename)
		input("Done..")
		


class Cryptor:

	def __init__(self,key):
		self.key = key

	def pad(self,s):
		return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

	def encrypt(self,message,key,key_size=256):
		message = self.pad(message)
		IV = Random.new().read(AES.block_size)
		cipher = AES.new(key,AES.MODE_CBC,IV)
		return IV + cipher.encrypt(message)

	def encrypt_file(self,file_name):
		with open(file_name,"rb") as fo:
			plaintext = fo.read()
		enc = self.encrypt(plaintext,self.key)
		bname = os.path.basename(file_name)
		l = len(file_name) - len(bname)
		outputfile = file_name[:l] + "(encrypted)" + bname
		with open(outputfile,"wb") as fo:
			fo.write(enc)
		os.remove(file_name)

	def decrypt(self,cipherText,key):
		IV = cipherText[:AES.block_size]
		cipher = AES.new(key,AES.MODE_CBC,IV)
		plaintext = cipher.decrypt(cipherText[AES.block_size:])
		return plaintext.rstrip(b"\0")

	def decrypt_file(self,file_name):
		with open(file_name,"rb") as fo:
			cipherText = fo.read()
		dec = self.decrypt(cipherText,self.key)
		bname = os.path.basename(file_name)
		l = len(file_name) - len(bname)
		outputfile = file_name[:l] + bname[11:]
		with open(outputfile,"wb") as fo:
			fo.write(dec)
		os.remove(file_name)

def main():
	proc = Main()
	choice = str(input("Encrypt or Decrypt ? (E)/(D) >"))
	if(choice in  ["E","D"]):
		proc.process(choice)
	else:
		print("Wrong Input")

if(__name__ == "__main__"):
	main()
