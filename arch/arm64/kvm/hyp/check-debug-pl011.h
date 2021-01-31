// PS:


/* **************************************************************************
 * additional debug printing functions, extending debug-pl011.h (some "plain",
 *  without the trailing \n)
 */


void hyp_putsp(char *s)
{
	while (*s)
		hyp_putc(*s++);
}

void hyp_putbool(bool b)
{
	if (b) hyp_putsp("true"); else hyp_putsp("false");
}


static inline void __hyp_putx4np(unsigned long x, int n)
{
	int i = n >> 2;

	hyp_putc('0');
	hyp_putc('x');

	while (i--)
		__hyp_putx4(x >> (4 * i));

}

void hyp_putsxn(char *s, unsigned long x, int n)
{
	hyp_putsp(s);
	hyp_putc(':');
	__hyp_putx4np(x,n);
	hyp_putc(' ');
}


void check_assert_fail(char *s)
{
	hyp_putsp("check_assert_fail: ");
	hyp_putsp(s);
	hyp_putc('\n');
}
