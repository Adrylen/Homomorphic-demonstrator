class Op
{
	public :
		bool negate;
		bool grey;

		Op()
		{
			negate = false;
			grey = false;
		}

		Op(const Op &autre)
		{
			negate = autre.negate;
			grey = autre.grey;
		}
};