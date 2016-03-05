ui:ui.c
	gcc ui.c -o ui `pkg-config --cflags --libs gtk+-2.0`
