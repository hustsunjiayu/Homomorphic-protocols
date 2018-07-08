import java.math.*;
import java.util.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
/**
 * @author HUSTCS CPSS sjy
 * all "new" functions are not suggested because of low efficiency
 */
public class PrivateCloud
{
	private BigInteger lambda;
	private BigInteger p, q;
	/**
	 * n = p*q, where p and q are two large primes.
	 */
	public BigInteger n;
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
    public static void main(String[] args) 
    {
        // TODO Auto-generated method stub
        PrivateCloud sever = new PrivateCloud();
        sever.run();
    }
    
    public void run() 
    {
        try 
        {
            server = new ServerSocket(2222);//local socket address
        } 
        catch (IOException e) 
        {
        	e.printStackTrace();
        }
        try 
        {
    		System.out.print("pk:\tn=" +n.toString()+"\n\t"+"g="+g.toString()+"\n");
    		System.out.print("sk:\tlambda=" +lambda.toString()+	 "\n");
    		System.out.println("waiting for the public clouds...");
            you = server.accept();
            br = new BufferedReader(new InputStreamReader(you.getInputStream()));
            pw = new PrintWriter(you.getOutputStream(), true);
            
            while ((inMessage = br.readLine()) != null) 
            {    
                switch(inMessage)
                {
                	case "*":secure_multiply();break;
                	case "LSB":secure_LSB();break;
                	case "SVR":SVR();break;
                	case ">":secure_compare();break;
                	case "ming/":SEDD();break;
                	default:System.out.println("get unidentified message:"+inMessage);break;
                }
            }
        } 
        catch (Exception e) {e.printStackTrace();}
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

	/**
	 * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where
	 * u = (L(g^lambda mod n^2))^(-1) mod n.
	 *
	 * @param c
	 *            ciphertext as a BigInteger
	 * @return plaintext as a BigInteger
	 */
	public BigInteger Decryption(BigInteger c) 
	{
		BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
		return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
	}

	/**
	 * sum of (cipher) em1 and em2
	 *
	 * @param em1
	 * @param em2
	 * @return
	 */
	public BigInteger cipher_add(BigInteger em1, BigInteger em2) 
	{
		return em1.multiply(em2).mod(nsquare);
	}


    String inMessage, outMessage;
    ServerSocket server = null;
    Socket you = null;
    String s = null;
    PrintWriter pw = null;
    BufferedReader br = null;
	String parameter1,parameter2;
	
    /**
     * @param args
     */
    public PrivateCloud() 
    {
        super();

        KeyGeneration();
    }

    
  
    /**
     * 
     * @param ea on the public cloud
     * @param b on the public cloud
     * @return [a/b] on the public cloud, but the private cloud knows nothing about any parameter
     */
    public void SEDD()
    {
    	try
    	{
    		parameter1=br.readLine();
    		BigInteger b=new BigInteger(parameter1);
    		parameter1=br.readLine();
    		BigInteger aprime=new BigInteger(parameter1);
    		outMessage = Encryption(Decryption(aprime).divide(b)).toString();
            pw.println(outMessage);
            pw.flush();
    		
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    	}
    }
    
    /**
     * 
     * @param ea on the public cloud
     * @param eb on the public cloud
     * @return [a>=b] on the public cloud, but the private cloud knows nothing about any parameter
     */
    public void secure_compare()
    {
    	/*restoring the codes with///////////////////!!!!!!!!!!!!!!!!!!!!!! 
    	 * on both the public and private cloud
    	 * can turn this function to BGK compare function
    	whose prototype is:   BigInteger BGK(ec,ed)  return [c>d]*/
    	int l=0;
    	try
    	{
			parameter1=br.readLine();//get l
			BigInteger paotui=new BigInteger(parameter1);
			l=paotui.intValue();
			parameter1=br.readLine();//get ez
			BigInteger ez=new BigInteger(parameter1);
			BigInteger z = Decryption(ez);
			BigInteger d = z.mod(BigInteger.valueOf(2).pow(l));
			BigInteger zdivide2l = Encryption(z.divide(BigInteger.valueOf(2).pow(l)));
			//d=z;///////////////////!!!!!!!!!!!!!!!!!!!!!!
			//run DGK protocol to compare c(c is in the client) and d
			int i;
			BigInteger dprime=d;
			for(i=0;i<l;i++)
			{
				//return every bit of d£¬[di], to the public cloud
				outMessage = Encryption(dprime.mod(BigInteger.valueOf(2))).toString();
	            pw.println(outMessage);
	            pw.flush();
	            dprime = dprime.shiftRight(1);
			}
			BigInteger result=BigInteger.ZERO;
			//get disordered [ci], if any ci is 0, deltaB is 1
			for(i=0;i<=l;i++)
			{
				
				parameter1=br.readLine();
				BigInteger eci=new BigInteger(parameter1);
				if(Decryption(eci).intValue()==0)
					result=BigInteger.ONE;
			}
			//return [deltaB] to the public cloud
			outMessage=Encryption(result).toString();
			pw.println(outMessage);
	        pw.flush();
	        
	        
	        //DGK ends
	        
	        //return [z¡Â2^l] to the public cloud
	        outMessage=zdivide2l.toString();
			pw.println(outMessage);
	        pw.flush();
    	}
    	catch(Exception e){}
    }
    
    /**
     * 
     * @param ea on the public cloud
     * @param eb on the public cloud
     * @return [a*b] on the public cloud, 
     * but the private cloud knows nothing about any parameter
     */
	public void secure_multiply()
	{
		try
		{
		 	parameter1 = br.readLine();
	 		BigInteger a = new BigInteger(parameter1);
	 		a=Decryption(a);
	 		parameter2 = br.readLine();
			BigInteger b = new BigInteger(parameter2);
			BigInteger a_multi_b = a.multiply(Decryption(b)).mod(n);
			outMessage = Encryption(a_multi_b).toString();
 		   	pw.println(outMessage);
 		   	pw.flush();
		}
		catch(Exception e){}
	}
	
	/**
	 * 
	 */
	public void secure_LSB()
	{
		try
		{
		 	while ((parameter1 = br.readLine()) != null)
		 	{
				BigInteger a = new BigInteger(parameter1);
				a=Decryption(a);
				
				outMessage = Encryption(a.mod(new BigInteger("2"))).toString();
   		   		pw.println(outMessage);
   		   		pw.flush();
				break;
		 	}
		}
		catch(Exception e){}
	}
	public void SVR()
	{
		try
		{
		 	while ((parameter1 = br.readLine()) != null)
		 	{
				BigInteger a = new BigInteger(parameter1);
				a=Decryption(a);
				if(a.intValue()==0)
				{
					outMessage="1";
				}
				else
					outMessage="0";
				pw.println(outMessage);
				pw.flush();
				break;
		 	}
		}
		catch(Exception e){}
	}
    
}
