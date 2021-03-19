TWT=twt
RM=rm
DD=dd
LIBS=-lcrypto
CFLAGS=-O2
SOURCES=twt.c

$(TWT): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	$(RM) $(TWT)

test:
	$(DD) bs=1024 count=1024 if=/dev/random of=test_a
	./$(TWT) -c encrypt -s test_a -d test_b
	./$(TWT) -c decrypt -s test_b -d test_c


