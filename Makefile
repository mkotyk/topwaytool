EXE=twt
RM=rm
LIBS=-lcrypto
CFLAGS=-O2
SOURCES=twt.c

$(EXE): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	$(RM) $(EXE)
