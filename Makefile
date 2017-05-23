#
# Design of ping
# 

LDFLAGS += -lpthread

FPIC = -fPIC
SHARED= -shared

SRCS = $(wildcard ./src/*.c)
OBJS=$(patsubst %.c,%.o,$(notdir $(SRCS)))

TARGET=ping

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJS):$(SRCS)
	$(CC) $(FPIC) $(CFLAGS) -c -o $@ $<


.PHONY:clean

clean:
	$(RM) $(TARGET) $(OBJS)
