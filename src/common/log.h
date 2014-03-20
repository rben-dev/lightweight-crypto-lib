/* Logging facilities */

#ifdef BASHCOLORS
#define ANSI_COLOR_RED     		"\x1b[31m"
#define ANSI_COLOR_GREEN  	 	"\x1b[32m"
#define ANSI_COLOR_YELLOW  		"\x1b[33m"
#define ANSI_COLOR_BLUE    		"\x1b[34m"
#define ANSI_COLOR_MAGENTA 		"\x1b[35m"
#define ANSI_COLOR_CYAN    		"\x1b[36m"
#define ANSI_COLOR_LBLUE		"\x1b[94m"
#define ANSI_COLOR_LGRAY		"\x1b[37m"
#define ANSI_COLOR_NONE    		""

#define ANSI_STYLE_BOLD			"\x1b[1m"
#define ANSI_STYLE_UNDERLINED 		"\x1b[4m"
#define ANSI_STYLE_INVERTED 		"\x1b[7m"
#define ANSI_STYLE_DIM			"\x1b[2m"
#define ANSI_STYLE_BLINK		"\x1b[5m"
#define ANSI_STYLE_HIDDEN		"\x1b[8m"
#define ANSI_STYLE_BOLDUNDERLINED	"\x1b[1m\x1b[4m"
#define ANSI_STYLE_NONE			""

#define ANSI_BACKGROUND_RED     	"\x1b[41m"
#define ANSI_BACKGROUND_GREEN		"\x1b[42m"
#define ANSI_BACKGROUND_YELLOW 		"\x1b[43m"
#define ANSI_BACKGROUND_BLUE   		"\x1b[44m"
#define ANSI_BACKGROUND_MAGENTA 	"\x1b[45m"
#define ANSI_BACKGROUND_CYAN    	"\x1b[46m"
#define ANSI_BACKGROUND_NONE    	""

#define ANSI_RESET   			"\x1b[0m"

#else

#define ANSI_COLOR_RED     		""
#define ANSI_COLOR_GREEN  	 	""
#define ANSI_COLOR_YELLOW  		""
#define ANSI_COLOR_BLUE    		""
#define ANSI_COLOR_MAGENTA 		""
#define ANSI_COLOR_CYAN    		""
#define ANSI_COLOR_LBLUE		""
#define ANSI_COLOR_LGRAY		""
#define ANSI_COLOR_NONE    		""

#define ANSI_STYLE_BOLD			""
#define ANSI_STYLE_UNDERLINED 		""
#define ANSI_STYLE_INVERTED 		""
#define ANSI_STYLE_DIM			""
#define ANSI_STYLE_BLINK		""
#define ANSI_STYLE_HIDDEN		""
#define ANSI_STYLE_BOLDUNDERLINED	""
#define ANSI_STYLE_NONE			""

#define ANSI_BACKGROUND_RED     	""
#define ANSI_BACKGROUND_GREEN		""
#define ANSI_BACKGROUND_YELLOW 		""
#define ANSI_BACKGROUND_BLUE   		""
#define ANSI_BACKGROUND_MAGENTA 	""
#define ANSI_BACKGROUND_CYAN    	""
#define ANSI_BACKGROUND_NONE    	""

#define ANSI_RESET   			""

#endif

unsigned char use_colors = 1;

typedef enum {red = 0, green = 1, yellow = 2, blue = 3, magenta = 4, cyan = 5, lblue = 6, lgray = 7, nocolor = 8} color;
const char* bash_colors[] = {ANSI_COLOR_RED, ANSI_COLOR_GREEN, ANSI_COLOR_YELLOW, ANSI_COLOR_BLUE, ANSI_COLOR_MAGENTA, ANSI_COLOR_CYAN, ANSI_COLOR_LBLUE, ANSI_COLOR_LGRAY, ANSI_COLOR_NONE};

typedef enum {bold = 0, underlined = 1, inverted = 2, dim = 3, blink = 4, hidden = 5, boldunderlined = 6, nostyle = 7} style;
const char* bash_styles[] = {ANSI_STYLE_BOLD, ANSI_STYLE_UNDERLINED, ANSI_STYLE_INVERTED, ANSI_STYLE_DIM, ANSI_STYLE_BLINK, ANSI_STYLE_HIDDEN, ANSI_STYLE_BOLDUNDERLINED, ANSI_STYLE_NONE};

typedef enum {redbg = 0, greenbg = 1, yellowbg = 2, bluebg = 3, magentabg = 4, cyanbg = 5, nobg = 6} background;
const char* bash_backgrounds[] = {ANSI_BACKGROUND_RED, ANSI_BACKGROUND_GREEN, ANSI_BACKGROUND_YELLOW, ANSI_BACKGROUND_BLUE, ANSI_BACKGROUND_MAGENTA, ANSI_BACKGROUND_CYAN, ANSI_BACKGROUND_NONE};

#ifdef BASHCOLORS
#define custom_printf(col, bg, st, format, ...) do {\
	if(use_colors == 1){\
		printf("%s%s%s"format ANSI_RESET, bash_colors[col], bash_backgrounds[bg], bash_styles[st], ##__VA_ARGS__);\
	}\
	else{\
		printf(format, ##__VA_ARGS__);\
	}\
} while(0);
#else
#define custom_printf(col, bg, st, ...) do {\
	printf(__VA_ARGS__);\
} while(0);
#endif

#define custom_printf_warning(...) do {\
	custom_printf(yellow, nobg, boldunderlined, "Warning:");\
	custom_printf(nocolor, nobg, nostyle, " ");\
	custom_printf(nocolor, nobg, nostyle, ##__VA_ARGS__);\
} while(0);

#define custom_printf_error(...) do {\
	custom_printf(red, nobg, boldunderlined, "Error:");\
	custom_printf(nocolor, nobg, nostyle, " ");\
	custom_printf(nocolor, nobg, nostyle, ##__VA_ARGS__);\
} while(0);

