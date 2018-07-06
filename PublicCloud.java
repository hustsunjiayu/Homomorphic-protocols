
import java.math.*;
import java.util.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;



/**
 * @author HUSTCS CPSS sjy
 * all "new" function is not suggested because of low efficiency
 */

public class PublicCloud
{
	public BigInteger p, q;
	public BigInteger n;
	public BigInteger lambda;
	String parameter1,parameter2;
	/**
	 * nsquare = n*n
	 */
	public BigInteger nsquare;
	/**
	 * a random integer in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
	 */
	private BigInteger g;
	/**
	 * number of bits of modulus
	 */
	private int bitLength;
	public BigInteger max_value;

	/**
	 * Sets up the default public key and private key.
	 */
	public void KeyGeneration() 
	{
		bitLength = 512;
		n = new BigInteger("6610448081029621072302925525349923040404783326050708223913843131800620511653885660987934214442318592515258311758963082370871109611512772945962762907448983");
		g = new BigInteger("2");
		lambda = new BigInteger("3305224040514810536151462762674961520202391663025354111956921565900310255826861399630215281138600142071785104723419946408306210843471157197175876323628324");
		nsquare = n.multiply(n);

	}

	/**
	 * Sets up the public key and private key.
	 *
	 * @param bitLengthVal
	 *            number of bits of modulus.
	 * @param certainty
	 *            The probability that the new BigInteger represents a prime
	 *            number will exceed (1 - 2^(-certainty)). The execution time of
	 *            this constructor is proportional to the value of this
	 *            parameter.
	 */
    public void KeyGeneration(int bitLengthVal, int certainty) {  
        bitLength = bitLengthVal;  
        /* 
         * Constructs two randomly generated positive BigIntegers that are 
         * probably prime, with the specified bitLength and certainty. 
         */  
        p = new BigInteger(bitLength / 2, certainty, new Random());  
        q = new BigInteger(bitLength / 2, certainty, new Random());  
  
        n = p.multiply(q);  
        nsquare = n.multiply(n);  
  
        g = new BigInteger("2");  
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))  
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));  
        /* check whether g is good. */  
        if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {  
            System.out.println("g is not good. Choose g again.");  
            System.exit(1);  
        }  
    }  

	/**
	 * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function
	 * explicitly requires random input r to help with encryption.
	 *
	 * @param m
	 *            plaintext as a BigInteger
	 * @param r
	 *            random plaintext to help with encryption
	 * @return ciphertext as a BigInteger
	 */
	public BigInteger Encryption(BigInteger m, BigInteger r) 
	{
		return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
	}

	/**
	 * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function
	 * automatically generates random input r (to help with encryption).
	 *
	 * @param m
	 *            plaintext as a BigInteger
	 * @return ciphertext as a BigInteger
	 */
	public BigInteger Encryption(BigInteger m) 
	{
		BigInteger r = new BigInteger(bitLength, new Random());
		return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

	}
	public BigInteger Encryption(long a) 
	{
		BigInteger m=BigInteger.valueOf(a);
		BigInteger r = new BigInteger(bitLength, new Random());
		return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

	}
	public BigInteger Decryption(BigInteger c) 
	{
		BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
		u=c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
		
		return u;
	}

   

    String inMessage, outMessage;

    String s = null;
    Socket mysocket;
    BufferedReader br = null;
    PrintWriter pw = null;

    BigInteger e1;
    BigInteger e0;
    /**
     * @param args
     */
    public PublicCloud() 
    {
        super();
        KeyGeneration();
        max_value = Encryption(Long.MAX_VALUE);
    }

    public static void main(String[] args) 
    {
        // TODO Auto-generated method stub
    	
        PublicCloud client = new PublicCloud();
        client.run();
    }
    
    
    
    /**
     * 
     * @param arr
     * @return the encrypted median of this encrypted array
     */
    public BigInteger mid(BigInteger[] arr)
    {
    	BigInteger res;
    	BigInteger[] a=new BigInteger[arr.length];
    	int i,j;
    	for(i=0;i<arr.length;i++)
    	{
    		a[i]=arr[i];
    	}
    	int need;
    	need=a.length/2+1;
    	for(i=0;i<need;i++)
    	{
    		for(j=1;j<a.length-i;j++)
    		{
    			
    			BigInteger c=SC(a[j],a[j-1]);
    			BigInteger temp=a[j];
    			a[j]=SA(SM(c,a[j]),SM(a[j-1],SS(e1,c)));
    			a[j-1]=SA(SM(c,a[j-1]),SM(temp,SS(e1,c)));
    		}
    	}
    	if(a.length%2==1)
    	{
    		res=a[a.length-need];
    	}
    	else
    	{
    		res=SEDD(SA(a[a.length-need],a[a.length-need+1]),BigInteger.valueOf(2));
    	}
    	
    	return res;
    }
    
    
    /**
     * 
     */
    public void run() 
    {
    	
    	long startTime,endTime;
        try 
        {            
        	System.out.println("pk:\tn=" +n.toString()+"\n\t"+"g="+g.toString()+"\n");
            mysocket = new Socket("127.0.0.1", 2222);//local socket address
            br = new BufferedReader(new InputStreamReader(
                    mysocket.getInputStream()));
            pw = new PrintWriter(mysocket.getOutputStream(), true);
            
            //test the protocol
            startTime= System.currentTimeMillis();
            BigInteger a=new BigInteger("4651348915");
        	BigInteger b=new BigInteger("10000");
        	endTime = System.currentTimeMillis();
        	System.out.println(a.toString()+"*"+b.toString()+"="+Decryption(SM(Encryption(a),Encryption(b))).toString());
        	System.out.println(a.toString()+"/"+b.toString()+"="+Decryption(SEDD(Encryption(a),b)).toString());
        	System.out.println("time cost:"+(startTime - endTime)+"ms");
            br.close();
        } 
        catch (Exception e) 
        {
        	e.printStackTrace();
        }
    }
    
    /**
     * secure compare protocol
     * @param ea [a] encrypted a
     * @param eb [b] encrypted b
     * @return [a>=b] encrypted 0 or 1 indicating if a>=b
     */
    public BigInteger  SC(BigInteger ea,BigInteger eb)
    {
    	/*restoring the codes with///////////////////!!!!!!!!!!!!!!!!!!!!!! 
    	 * can turn this function to BGK compare function
    	whose prototype is:   BigInteger BGK(ec,ed)  return [c>d]*/
    	int l1 = 0, l2 = 0;
    	try{
    		l1 = secure_SBD(ea).length;
        	l2 = secure_SBD(eb).length;
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    		System.out.println("a="+Decryption(ea));
    		System.out.println("b="+Decryption(eb));
    		BigInteger c = SC(SA(ea, max_value), SA(eb, max_value));
    		System.out.println("c = "+Decryption(c));
    		return c;
    	}
    	
    	if(l1>l2)
    		return e1;
    	if(l2>l1)
    		return e0;
    	int l = l1;
    	//send request to the server
    	outMessage = ">";
    	pw.println(outMessage);
    	pw.flush();
    	//send the first para, the length l
    	outMessage = String.valueOf(l);
    	pw.println(outMessage);
    	pw.flush();
    	
    	BigInteger r = new BigInteger(l+80, new Random());
    	BigInteger twoL = BigInteger.valueOf(2).pow(l);
    	BigInteger ez = ea.multiply(Encryption(twoL.add(r)))
    			.multiply(eb.modPow(n.subtract(BigInteger.ONE), nsquare)).mod(nsquare);
    	//[z]=[a-b+2^l+r]
    	//ez=eb;///////////////////!!!!!!!!!!!!!!!!!!!!!!
    	//the 2th para,[z]
    	outMessage = ez.toString();
    	pw.println(outMessage);
    	pw.flush();
    	BigInteger c = r.mod(twoL);
    	
    	//run DGK protocol to compare c and d(d is in the server)
    	//c=Decryption(ea);///////////////////!!!!!!!!!!!!!!!!!!!!!!
    	int i;
    	BigInteger[] cxordbits = new BigInteger[l];//[ci xor di] in cxordbits 
    	BigInteger[] edbits = new BigInteger[l];//every bit of [di]
    	BigInteger cprime = c;
    	BigInteger[] ci = new BigInteger[l];//the first element is the lowest bit of c
	    try
	    {
	    	for(i=0;i<l;i++)
	    	{
	    		//receive every bit of [di] from the server
	    		parameter1=br.readLine();
	    		BigInteger edi = new BigInteger(parameter1);
	    		edbits[i]=edi;
	    		ci[i]=cprime.mod(BigInteger.valueOf(2));
	    		cxordbits[i]=(ci[i].intValue()==1)
	    				?Encryption(BigInteger.valueOf(1))
	    						.multiply(edi.modPow(n.subtract(BigInteger.ONE), nsquare)).mod(nsquare)
	    				:edi;
	    		cprime=cprime.shiftRight(1);
	    	}
	    	i=(int)(Math.random()*100);
	    	
	    	BigInteger deltaA=BigInteger.valueOf(i%2);
	    	//[s]=[1-2*deltaA]
	    	BigInteger es=e1;
	    	if(deltaA.intValue()==1)
	    		es=es.modPow(n.subtract(BigInteger.ONE), nsquare);
	    	cprime = c;
	    	//ec is for calculating deltaB, not the real [c]
	    	BigInteger[] ec=new BigInteger[l+1];
	    	for(i=0;i<l;i++)
	    	{
	    		//[ci]=[ci*ri],if the server finds any ci is 0£¬then deltaB is 1£¬else deltaB is 0
	    		BigInteger ri = new BigInteger(bitLength, new Random());
	    		if(ci[i].compareTo(deltaA)==0)
	    		{
	    			int j;
		    		BigInteger temp=new BigInteger("1");
		    		for(j=i+1;j<l;j++)
		    		{
		    			temp=temp.multiply(cxordbits[j]).mod(nsquare);
		    		}
		    		ec[i]=temp;
		    		if(deltaA.intValue()==0)
		    		{
		    			ec[i]=SA(SS(e1, edbits[i]),ec[i]);
		    		}
		    		else
		    		{
		    			ec[i]=SA(edbits[i],ec[i]);
		    		}
	    			ec[i]=ec[i].modPow(ri, nsquare);
	    		}
	    		else
	    			ec[i]=Encryption(ri);
	    		
	    	}
	    	ec[l]=Encryption(deltaA);
	        for(i=0;i<l;i++)
	        {
	        	ec[l]=ec[l].multiply(cxordbits[i]).mod(nsquare);
	        }
	    	
	    	//disorder the [c] and send them to the server
	    	Random rand = new Random();
	    	for(i=l;i>0;i--)
	    	{
	    		
	    		BigInteger temp=ec[i];
	    		int ex=rand.nextInt(i);
	    		ec[i]=ec[ex];
	    		ec[ex]=temp;
	    	}
	    	for(i=0;i<=l;i++)
	    	{
	    		outMessage=ec[i].toString();
	    		pw.println(outMessage);
	        	pw.flush();
	    	}
	    	//receive [deltaB] from the server
	    	parameter1=br.readLine();
	    	BigInteger edeltaB=new BigInteger(parameter1);

            BigInteger eresult0=(deltaA.intValue()==0)
	    			?e1.multiply(edeltaB.modPow(n.subtract(BigInteger.ONE), nsquare))
	        				.mod(nsquare)
	    			:edeltaB;
	        
	    	//DGK ends, get eresult0=[d<c]
	    	
	    	BigInteger eresult=Encryption(r.divide(twoL)).multiply(eresult0).mod(nsquare)
	    			.modPow(n.subtract(BigInteger.ONE), nsquare);
	    	//receive [z¡Â2^l] from the server
	    	parameter1=br.readLine();
	    	BigInteger eztwoL =new BigInteger(parameter1);
	    	eresult=eresult.multiply(eztwoL).mod(nsquare);
	    	//eresult=eresult0;///////////////////!!!!!!!!!!!!!!!!!!!!!!
	    	return eresult;
	    }
	    catch(Exception e){e.printStackTrace();}
    	return BigInteger.ZERO;
    	
    }
    
    //another kind of SC protocol, but with low efficiency, not suggested
    public BigInteger SCnew(BigInteger a, BigInteger b)
    {
    	BigInteger[] abits0 = secure_SBD(a);
    	BigInteger[] bbits0 = secure_SBD(b);
    	if(abits0.length>bbits0.length)
    		return e1;
    	if(abits0.length<bbits0.length)
    		return e0;
    	int maxlength = Math.max(abits0.length, bbits0.length);
    	
    	BigInteger[][] bits = new BigInteger[2][maxlength];
    	for(int i=0;i<maxlength;i++)
    	{
    		bits[0][i] = e0;
    		bits[1][i] = e0;
    	}
    	
    	for(int i=abits0.length-1;i>=0;i--)
    	{
    		bits[0][i-abits0.length+maxlength] = abits0[abits0.length-1-i];
    	}
    	for(int i=bbits0.length-1;i>=0;i--)
    	{
    		bits[1][i-bbits0.length+maxlength] = bbits0[bbits0.length-1-i];
    	}
    	int n=2;
    	
    	BigInteger[] s = new BigInteger[n];
    	for(int i=0;i<n;i++)
    		s[i] = e1;
    	BigInteger[] d = new BigInteger[maxlength];
    	
    	for(int i=0;i<maxlength;i++)
    	{
    		for(int j=0;j<n;j++)
    		{
    			bits[j][i] = SAND(bits[j][i], s[j]);
    		}
    		d[i] = bits[0][i];
    		for(int j=1;j<n;j++)
    		{
    			d[i] = SOR(d[i], bits[j][i]);
    		}
    		for(int j=0;j<n;j++)
    		{
    			s[j] = SAND(s[j], SS(e1, SAND(d[i], SS(e1, bits[j][i]))));
    		}
    	}
    	BigInteger res = SEQUALnew(d, bits[0]);
    	return res;
    }
    
    
    public BigInteger SMAXnINDEX(BigInteger []a)
    {
    	BigInteger max = a[0], index = e0;
    	for(int i=1;i<a.length;i++)
    	{
    		BigInteger c = SC(max, a[i]);
    		index = SA(SM(c, index), SM(SS(e1, c), Encryption(i)));
    	}
    	return index;
    }
    
    
    public BigInteger SEQUAL(BigInteger a, BigInteger b)
    {
    	BigInteger c1 = SC(a, b);
    	BigInteger c2 = SC(b, a);
    	return SM(c1, c2);
    }
    
  //another kind of SEQUAL protocol, but with low efficiency, not suggested
    public BigInteger SEQUALnew(BigInteger a, BigInteger b)
    {
    	BigInteger[] abits0 = secure_SBD(a);
    	BigInteger[] bbits0 = secure_SBD(b);
    	if(abits0.length!=bbits0.length)
    		return e0;
    	int maxlength = Math.max(abits0.length, bbits0.length);
    	BigInteger[] abits = new BigInteger[maxlength];
    	BigInteger[] bbits = new BigInteger[maxlength];
    	for(int i=0;i<maxlength;i++)
    	{
    		abits[i] = e0;
    		bbits[i] = e0;
    	}
    	for(int i=abits0.length-1;i>=0;i--)
    	{
    		abits[i-abits0.length+maxlength] = abits0[abits0.length-1-i];
    	}
    	for(int i=bbits0.length-1;i>=0;i--)
    	{
    		bbits[i-bbits0.length+maxlength] = bbits0[bbits0.length-1-i];
    	}
    	BigInteger[] xor = new BigInteger[maxlength];
    	for(int i=0;i<maxlength;i++)
    	{
    		xor[i] = SXOR(abits[i], bbits[i]);
    	}
    	BigInteger res = e0;
    	for(int i=0;i<maxlength;i++)
    	{
    		res = SOR(res, xor[i]);
    	}
    	return SS(e1,res);
    }
    
    
//    same as BigInteger SEQUALnew(BigInteger a, BigInteger b)
    public BigInteger SEQUALnew(BigInteger[] abits, BigInteger[] bbits)
    {
    	int maxlength = abits.length;
    	BigInteger[] xor = new BigInteger[maxlength];
    	for(int i=0;i<maxlength;i++)
    	{
    		xor[i] = SXOR(abits[i], bbits[i]);
    	}
    	BigInteger res = e0;
    	for(int i=0;i<maxlength;i++)
    	{
    		res = SOR(res, xor[i]);
    	}
    	return SS(e1,res);
    }
    

    public BigInteger SMIN(BigInteger a,BigInteger b)
    {
    	BigInteger c = SC(a, b);
    	BigInteger res = SA(SM(c, b), SM(SS(e1, c), a));
    	return res;
    }
    
    
/**
 * all "new" function is not suggested because of low efficiency
 * @param a
 * @param b
 * @return
 */
    public BigInteger SMINnew(BigInteger a,BigInteger b)
    {
    	BigInteger[] x = new BigInteger[2];
    	x[0] = a;
    	x[1] = b;
    	return SMINnnew(x);
    }
    
    public BigInteger SMINnnew(BigInteger []a)
    {
    	int n = a.length;// n numbers
    	BigInteger[][] bits0 = new BigInteger[n][];
    	int maxlength=0;
    	for(int i=0;i<n;i++)
    	{
    		bits0[i] = secure_SBD(a[i]);
    		maxlength = Math.max(maxlength, bits0[i].length);
    	}
    	BigInteger[][] bits = new BigInteger[n][maxlength];
    	for(int i=0;i<n;i++)
    	{
    		for(int j=0;j<maxlength;j++)
    		{
    			bits[i][j] = e0;
    		}
    	}
    	for(int i=0;i<n;i++)
    	{
    		for(int j=bits0[i].length-1;j>=0;j--)
    		{
    			bits[i][j+maxlength-bits0[i].length] = bits0[i][bits0[i].length-1-j];
    			
    		}
    	}
    	
    	BigInteger[] s = new BigInteger[n];
    	for(int i=0;i<n;i++)
    		s[i] = e0;
    	BigInteger[] d = new BigInteger[maxlength];
    	BigInteger res = e0;
    	for(int i=0;i<maxlength;i++)
    	{
    		for(int j=0;j<n;j++)
    		{
    			bits[j][i] = SOR(bits[j][i], s[j]);
    		}
    		d[i] = bits[0][i];
    		for(int j=1;j<n;j++)
    		{
    			d[i] = SAND(d[i], bits[j][i]);
    		}
    		for(int j=0;j<n;j++)
    		{
    			s[j] = SOR(s[j], SXOR(d[i], bits[j][i]));
    		}
    		
    		res = SA(SDM(res, 2),d[i]);
    	}
    	return res;
    }
    
    public BigInteger SMAX(BigInteger a,BigInteger b)
    {
    	BigInteger c = SC(a, b);
    	BigInteger res = SA(SM(c, a), SM(SS(e1, c), b));
    	return res;
    }
    
    public BigInteger SMAXnew(BigInteger a,BigInteger b)
    {
    	BigInteger[] x = new BigInteger[2];
    	x[0] = a;
    	x[1] = b;
    	return SMAXnnew(x);
    }
    
    
    
    public BigInteger SMAXn(BigInteger[] a)
    {
    	BigInteger res = a[0];
    	for(int i=1;i<a.length;i++)
    	{
    		BigInteger c = SC(res, a[i]);
    		res = SA(SM(c, res), SM(SS(e1, c), a[i]));
    	}
    	return res;
    }
    
    
    public BigInteger SMAXnnew(BigInteger[] a)
    {
    	int n = a.length;// n numbers
    	BigInteger[][] bits0 = new BigInteger[n][];
    	int maxlength=0;
    	for(int i=0;i<n;i++)
    	{
    		bits0[i] = secure_SBD(a[i]);
    		maxlength = Math.max(maxlength, bits0[i].length);
    	}
    	BigInteger[][] bits = new BigInteger[n][maxlength];
    	for(int i=0;i<n;i++)
    	{
    		for(int j=0;j<maxlength;j++)
    		{
    			bits[i][j] = e0;
    		}
    	}
    	for(int i=0;i<n;i++)
    	{
    		for(int j=bits0[i].length-1;j>=0;j--)
    		{
    			bits[i][j+maxlength-bits0[i].length] = bits0[i][bits0[i].length-1-j];
    			
    		}
    	}
    	
    	BigInteger[] s = new BigInteger[n];
    	for(int i=0;i<n;i++)
    		s[i] = e1;
    	BigInteger[] d = new BigInteger[maxlength];
    	BigInteger res = e0;
    	for(int i=0;i<maxlength;i++)
    	{
    		for(int j=0;j<n;j++)
    		{
    			bits[j][i] = SAND(bits[j][i], s[j]);
    		}
    		d[i] = bits[0][i];
    		for(int j=1;j<n;j++)
    		{
    			d[i] = SOR(d[i], bits[j][i]);
    		}
    		for(int j=0;j<n;j++)
    		{
    			s[j] = SAND(s[j], SS(e1, SAND(d[i], SS(e1, bits[j][i]))));
    		}
    		
    		res = SA(SDM(res, 2),d[i]);
    	}
    	return res;
    }
    
    /**
     * 
     * @param ex
     * @return encrypted squareroot of x
     */
    public BigInteger SQ(BigInteger ex)
    {
    	
    	int len=secure_SBD(ex).length;   
    	BigInteger er=e0;
    	long e=(long) Math.pow(2, len/2);
    	BigInteger ee=Encryption(BigInteger.valueOf(e));
    	int k;
    	BigInteger et,ec;
    	BigInteger eone=e1;
    	for(k=0;k<=len/2-1;k++)
    	{
    		et=SA(er.pow(2),ee).modPow(BigInteger.valueOf(e), nsquare);
    		ec=SC(ex,et);
    		er=SA(SM(ec,SA(er,ee)),SM(SS(eone,ec),er));
    		ex=SA(SM(ec,SS(ex,et)),SM(SS(eone,ec),ex));
    		e=e/2;
    		ee=ee.modPow(BigInteger.valueOf(2).modInverse(nsquare), nsquare);
    	}
    	return er;
    }
    
/**
 * 
 * @param ea
 * @param eb
 * @return [a/b]
 */
    public BigInteger SD(BigInteger ea,BigInteger eb)
    {

    	BigInteger[] eabits=secure_SBD(ea);
    	BigInteger[] ebbits=secure_SBD(eb);
    	int la=eabits.length;
    	int lb=ebbits.length;
    	int lq=la-lb+1;
    	if(lq<=0)
    	{
    		return e0;
    	}
    	BigInteger[] eqbits=new BigInteger[lq];
    	BigInteger epa=e0;
    	int i;
    	long mi=1;
    	for(i=la-lb;i<la;i++)
    	{
    		epa=eabits[i].modPow(BigInteger.valueOf(mi),nsquare).multiply(epa).mod(nsquare);
    		mi=mi*2;
    	}
    	
    	for(i=lq-1;i>=0;i--)
    	{
    		BigInteger edif=eb.modPow(n.subtract(BigInteger.ONE), nsquare).multiply(epa).mod(nsquare);

    		eqbits[i]=SC(epa,eb);

    		BigInteger er=SM(eqbits[i],edif);
    		er=er.multiply(SM(e1
				.multiply(eqbits[i].modPow(n.subtract(BigInteger.ONE), nsquare)).mod(nsquare),epa)).mod(nsquare);
    		if(i>=1)
    		{
    			epa=er.pow(2).mod(nsquare).multiply(eabits[i-1]).mod(nsquare);
    		}
    	}
    	BigInteger eq=new BigInteger("1");
    	mi=1;
    	for(i=0;i<lq;i++)
    	{
    		eq=eqbits[i].modPow(BigInteger.valueOf(mi),nsquare).multiply(eq).mod(nsquare);
    		mi=mi*2;
    	}
    	return eq;
    }
    
    /**
     * 
     * @param ea
     * @param b
     * @return [a/b]
     */
    public BigInteger SEDD(BigInteger ea,BigInteger b)
    {
    	outMessage = "ming/";
    	pw.println(outMessage);
    	pw.flush();
    	outMessage = b.toString();
    	pw.println(outMessage);
    	pw.flush();
       	BigInteger r=new BigInteger(bitLength/2, new Random());
    	BigInteger eaprime=SA(ea,Encryption(r.multiply(b)));
    	outMessage = eaprime.toString();
    	pw.println(outMessage);
    	pw.flush();
    	try
    	{
    		parameter1=br.readLine();
    		BigInteger rest=new BigInteger(parameter1);
    		return SS(rest,Encryption(r));
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();	
    	}
    	return BigInteger.ZERO;
    }
    
    
   
    
    
    
    
/**
 * 
 * @param ea
 * @param eb
 * @return [a*b]
 */
	public BigInteger SM(BigInteger ea,BigInteger eb)
	{

		outMessage="*";
		pw.println(outMessage);
		pw.flush();
		BigInteger ra=new BigInteger(bitLength, new Random());
		BigInteger rb=new BigInteger(bitLength, new Random());
  
		outMessage = ea.multiply(Encryption(ra)).mod(nsquare).toString();
		pw.println(outMessage);
		pw.flush();
  
		outMessage=eb.multiply(Encryption(rb)).mod(nsquare).toString();
		pw.println(outMessage);
		pw.flush();
  	
		BigInteger result = new BigInteger("0");
		try
		{
			while ((inMessage = br.readLine()) != null) 
			{
	  			result = new BigInteger(inMessage);
	  			result = result.multiply(ea.modPow(n.subtract(rb),nsquare)).mod(nsquare);
	  			result = result.multiply(eb.modPow(n.subtract(ra),nsquare)).mod(nsquare);
	  			result = result.multiply(Encryption(ra.multiply(rb)).mod(nsquare)
	  					.modPow(n.subtract(BigInteger.ONE),nsquare)).mod(nsquare);
	            break;
			}
		}
		catch(Exception e){}
		return result;	
	}			
	
	/**
	 * 
	 * @param ea
	 * @param b
	 * @return [a*b]
	 */
	public BigInteger SDM(BigInteger ea,BigInteger b)
	{
		return ea.modPow(b, nsquare);
	}
	
	/**
	 * 
	 * @param ea
	 * @param b
	 * @return [a*b]
	 */
	public BigInteger SDM(BigInteger ea,long b)
	{
		return ea.modPow(BigInteger.valueOf(b), nsquare);
	}
	
	/**
	 * 
	 * @param ea
	 * @param eb
	 * @return [a+b]
	 */
	public BigInteger SA(BigInteger ea,BigInteger eb)
	{
		BigInteger ec;
		ec=ea.multiply(eb).mod(nsquare);
		return ec;
	}
	/**
	 * 
	 * @param ea
	 * @param eb
	 * @return [a-b]
	 */
	public BigInteger SS(BigInteger ea,BigInteger eb)
	{
		BigInteger ec;
		ec=eb.modPow(n.subtract(BigInteger.ONE), nsquare).multiply(ea).mod(nsquare);
		return ec;
	}
	
	/**
	 * 
	 * @param ea a is a bit
	 * @param eb b is a bit
	 * @return [a or b] 
	 */
	public BigInteger SOR(BigInteger ea, BigInteger eb)
	{
		BigInteger res = SA(ea, eb);
		res = SS(res, SM(ea, eb));
		return res;
	}
	/**
	 * 
	 * @param ea a is a bit
	 * @param eb b is a bit
	 * @return [a and b] 
	 */
	public BigInteger SAND(BigInteger ea, BigInteger eb)
	{
		return SM(ea, eb);
	}
	/**
	 * 
	 * @param ea a is a bit
	 * @param eb b is a bit
	 * @return [a xor b] 
	 */
	public BigInteger SXOR(BigInteger ea, BigInteger eb)
	{
		BigInteger res = SA(ea, eb);
		res = SS(res, SDM(SM(ea, eb), BigInteger.valueOf(2)));
		return res;
	}
	
	/**
	 * 
	 * @param ea
	 * @return [a is odd]
	 */
	public BigInteger secure_LSB(BigInteger ea)
	{
		outMessage="LSB";
		pw.println(outMessage);
		pw.flush();
      
		BigInteger r=new BigInteger(bitLength-2, new Random());
		outMessage=ea.multiply(Encryption(r)).mod(nsquare).toString();
		//outMessage=a.toString();
		pw.println(outMessage);
		pw.flush();
      
		BigInteger result = new BigInteger("0");
		try
		{
			while ((inMessage = br.readLine()) != null) 
      		{
      			result = new BigInteger(inMessage);
      			if(r.mod(new BigInteger("2")).intValue()==1)
      			{
      				result=e1.multiply(result.modPow(n.subtract(BigInteger.ONE),nsquare)).mod(nsquare);
      			}
      			break;
      		}
        
		}
		catch(Exception e){}
		return result;
	}


	/**
	 * 
	 * @param [a]
	 * @return every encrypted bit of a, the first element is the lowest bit
	 */
	public BigInteger[] secure_SBD(BigInteger a)
	{
		BigInteger l=new BigInteger("2"),aprime=a;
		l=l.modInverse(n);
		
		BigInteger[] bitsOfa=new BigInteger[bitLength];
		BigInteger u=new BigInteger("1");
		int i=0;//bitCount(a);
		for(;;i++)
		{
			
			bitsOfa[i]=secure_LSB(aprime);
			
			//SVR begin
			outMessage="SVR";
			pw.println(outMessage);
			pw.flush();
			u=u.multiply(bitsOfa[i].modPow(new BigInteger("2").pow(i), nsquare)).mod(nsquare);
			BigInteger v=u.multiply(a.modPow(n.subtract(BigInteger.ONE), nsquare)).mod(nsquare);
			v=v.modPow(new BigInteger(bitLength,new Random()), nsquare);
			outMessage=v.toString();
			pw.println(outMessage);
			pw.flush();
			try
			{
				while ((inMessage = br.readLine()) != null)
	      		{
	      			if(inMessage.equals("1"))
	      			{
	      				BigInteger[] result=new BigInteger[i+1];
	      				int j;
	      				for(j=0;j<=i;j++)
	      					result[j]=bitsOfa[j];
	      				return result;
	      			}
	      			break;
	      		}
			}
			catch(Exception e){e.printStackTrace();}
			//SVR end
			aprime=aprime.multiply(bitsOfa[i].modPow(n.subtract(BigInteger.ONE), nsquare)).mod(nsquare);
			aprime=aprime.modPow(l, nsquare);
		}
	}
	
	

}
