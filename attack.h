/**
 * \author H{\aa}vard Raddum
 *
 * Code for testing the attack on Rubato with weak q's.  The DGS library https://github.com/malb/dgs 
 * is required and used for generating discrete Gaussians over the integers 
 **/

#include <dgs/dgs_gauss.h>

dgs_disc_gauss_dp_t *DGS;//the discrete Gaussian sampler
double sigma;//variance of the DGS
long length=10000;//length of known key stream
int I1, I2;//indicating when values from DGS modulo small m are sampled at a frequency higher or lower than 1/m

void initDGS(){
  DGS=dgs_disc_gauss_dp_init(sigma,0.0,80,DGS_DISC_GAUSS_DEFAULT);
}

long *realKeyStream(cipherState *K, long nr){
  /* Generates <length> elements of nr-round Rubato keystream including noise and returns it in an array. */
  long *ret, i, l, c=0, e;
  cipherState *S;

  ret=(long *)malloc(length*sizeof(long));
  l=v*v-4;//number of elements taken from each cipher state
  srandom(IV);
  while(c<length){
    S=rubatoBlock(K,nr);
    for(i=0; i<l && c<length; ++i)
      ret[c++]=S->matrix[i/v][i%v];
    deleteState(S);
  }
  for(i=0; i<length; ++i){//adds all noise in the end to ensure same outputs from XOF when re-seeding with IV
    e=(long)DGS->call(DGS);
    ret[i]=(ret[i]+e+Q)%Q;
  }
      
  return ret;
}

void newModulus(long *KS){
  /* Reduces all entries in KS modulo the (presumably) new Q. */
  long i;

  for(i=0; i<length; ++i)
    KS[i]=KS[i]%Q;
}

long *guessKeyStream(cipherState *K, int nr){
  /* Generates <length> elements of nr-round Rubato key stream without noise and returns it in an array. */
  long *ret, i, l, c=0;
  cipherState *S;

  ret=(long *)malloc(length*sizeof(long));
  l=v*v-4;//number of elements taken from each cipher state
  srandom(IV);
  while(c<length){
    S=rubatoBlock(K,nr);
    for(i=0; i<l && c<length; ++i)
      ret[c++]=S->matrix[i/v][i%v];
    deleteState(S);
  }

  return ret;
}

void fixI1andI2(){
  /* Determines when pr_m(x) is smaller and larger than 1/m. */
  double base, *pr, aq, uni, expsc;
  int i, x;
  unsigned char found=0;

  aq=sigma*sqrt(2.0*M_PI);
  base=pow(M_E,-1.0/(2.0*sigma*sigma));
  pr=(double *)malloc(Q*sizeof(double));
  
  for(x=0; x<Q; ++x){
    pr[x]=0.0;
    for(i=(-60/Q)*Q+x; i<60; i+=Q)
      pr[x]+=pow(base,(double)(i*i));
    pr[x]/=aq;
  }
  uni=1.0/(double)Q;
  I1=0;
  while(pr[I1]>=uni)
    I1++;
  I2=I1;
  while(pr[I2]<uni && I2<Q)
    I2++;
  expsc=0.0;
  for(i=0; i<I1; ++i)
    expsc+=pr[i]-uni;
  for(i=I1; i<I2; ++i)
    expsc+=uni-pr[i];
  for(i=I2; i<Q; ++i)
    expsc+=pr[i]-uni;
  printf("I1=%d, I2=%d, expecting score %1.4f for correct key guess\n",I1,I2,expsc);
}

double score(long *canNoise){
  /* computes how much canNoise deviate from uniform distribution, in the Gaussian direction.
     High score indicates correct key guess mod Q. */
  double ret, uni;
  long i, *count;

  uni=1.0/(double)Q;//probability for uniform distribution
  count=(long *)calloc(Q,sizeof(long));
  for(i=0; i<length; ++i)
    count[canNoise[i]]++;

  for(i=0; i<I1; ++i)
    ret+=((double)count[i])/((double)length)-uni;
  for(i=I1; i<I2; ++i)
    ret+=uni-((double)count[i])/((double)length);
  for(i=I2; i<Q; ++i)
    ret+=((double)count[i])/((double)length)-uni;

  return ret;
}

void fixGuess80S(cipherState *guessK, long bp){
  /* Fills last row of guessK with values indicated by bp. */
  int i, m, wbp;

  wbp=bp;
  for(i=0; i<4; ++i){
    m=wbp%Q;
    guessK->matrix[3][i]=m;
    wbp/=Q;
  }
}

void fixGuess80M(cipherState *guessK, long bp){
  /* Fills last 10 elements of guessK with values indicated by bp. */
  int i, m, wbp;

  wbp=bp;
  for(i=2; i<6; ++i){
    m=wbp%Q;
    guessK->matrix[4][i]=m;
    wbp/=Q;
  }
  for(i=0; i<6; ++i){
    m=wbp%Q;
    guessK->matrix[5][i]=m;
    wbp/=Q;
  }
}

void fixGuess80L2(cipherState *guessK, long bp){
  /* Fills last two rows of guessK with values indicated by bp. */
  int i;

  for(i=0; i<16; ++i){
    if(bp&(1<<i))
      guessK->matrix[6+i/v][i%v]=1;
    else
      guessK->matrix[6+i/v][i%v]=0;      
  }
}

void fixGuess128S(cipherState *guessK, long bp){
  /* Fills last row of guessK with values indicated by bp. */
  int i, m, wbp;

  wbp=bp;
  for(i=0; i<4; ++i){
    m=wbp%Q;
    guessK->matrix[3][i]=m;
    wbp/=Q;
  }
}

void fixGuess128M(cipherState *guessK, long bp){
  /* Fills last 6 elements of guessK with values indicated by bp. */
  int i, m, wbp;

  wbp=bp;
  for(i=0; i<6; ++i){
    m=wbp%Q;
    guessK->matrix[5][i]=m;
    wbp/=Q;
  }
}
