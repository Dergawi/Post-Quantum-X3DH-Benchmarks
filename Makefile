all:
	cd ./src/SKEM_KEM_SIG && make
	cd ./src/KEM_SIG && make
	cd ./src/KEM_RS && make
	cd ./src/KEM_DVS && make
	cd ./src/DH && make

clean:
	cd ./src/SKEM_KEM_SIG && make clean
	cd ./src/KEM_SIG && make clean
	cd ./src/KEM_RS && make clean
	cd ./src/KEM_DVS && make clean
	cd ./src/DH && make clean
