TARGET=Fuzzer

#File
jsonEXE=FuzzJson
packetEXE=FuzzPacket
driversEXE=FuzzDrivers
driversStructuredEXE=FuzzDriversStructured
clientEXE=FuzzClient

#Compiler Flags
DIR=$(shell ls -d ../gpsd*~dev/)
INC=-I$(DIR)include/
EXTCFLAGS=-Wall -Werror -pthread -std=c99
LibINC=-L$(DIR)
LibFLAGS=$(LIB_FUZZING_ENGINE) -lgpsd -lgps_static

all: $(TARGET)

#SETUP
$(TARGET):
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(jsonEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(packetEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(driversEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(driversStructuredEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(clientEXE).c

	$(CXX) $(CFLAGS) $(LibINC) -o $(jsonEXE) $(jsonEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(packetEXE) $(packetEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(driversEXE) $(driversEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(driversStructuredEXE) $(driversStructuredEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(clientEXE) $(clientEXE).o  $(LibFLAGS)

clean:
	rm $(jsonEXE) $(packetEXE) $(driversEXE) $(driversStructuredEXE) $(clientEXE) *.o

.PHONY: all clean
