/**
 * 
 * \author H{\aa}vard Raddum
 *
 * Code implementing Rubato without noise, using C's built-in random() function as XOF.
 *  
 */

long Q, OLDQ;//Rubato modulus, and original Rubato modulus (for generating exactly the same coefficients from the XOF)
long v;//Rubato state size
long IV=1234;//seed for the XOF

typedef struct cipher_state{
  long **matrix;//the actual matrix
} cipherState;

cipherState *MDS, *MDS_T;//MDS and MDS transpose

long gcd(long a, long b){
  /* Returns gcd(a,b).  Used to check that coefficients multiplied on Rubato master key are in Z_Q^*. */
  long g;

  if(a==0)
    return b;
  if(b==0)
    return a;
  g=b%a;
  if(g==0)
    return a;

  return gcd(g,a);
}

cipherState *newState(){
  /* Initializes a cipher state of size N x N, filled with 0's. */
  long i;
  cipherState *ret;

  ret=(cipherState *)malloc(sizeof(cipherState));
  ret->matrix=(long **)malloc(v*sizeof(long *));
  for(i=0; i<v; ++i)
    ret->matrix[i]=(long *)calloc(v,sizeof(long));
  
  return ret;
}

void deleteState(cipherState *S){
  /* Frees all memory allocated in S. */
  long i;

  for(i=0; i<v; ++i)
    free(S->matrix[i]);
  free(S->matrix);
  free(S);
}

cipherState *initialRubatoState(){
  /* Creates and returns the initial state in Rubato. */
  cipherState *ret;
  long i, j;

  ret=newState();
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j)
      ret->matrix[i][j]=v*i+j+1;
  }

  return ret;
}

void initMDSmatrices(){
  /* Initializes correct MDS matrix, according to N. */
  long i, j;
  
  MDS=newState();
  switch(v){
  case 4:
    MDS->matrix[0][0]=2; MDS->matrix[0][1]=3; MDS->matrix[0][2]=1; MDS->matrix[0][3]=1;
    for(i=1; i<v; ++i){
      for(j=0; j<v; ++j)
	MDS->matrix[i][j]=MDS->matrix[i-1][(j-1+v)%v];
    }
    break;
  case 6:
    MDS->matrix[0][0]=4; MDS->matrix[0][1]=2; MDS->matrix[0][2]=4;
    MDS->matrix[0][3]=3; MDS->matrix[0][4]=1; MDS->matrix[0][5]=1;
    for(i=1; i<v; ++i){
      for(j=0; j<v; ++j)
	MDS->matrix[i][j]=MDS->matrix[i-1][(j-1+v)%v];
    }
    break;
  case 8:
    MDS->matrix[0][0]=5; MDS->matrix[0][1]=3; MDS->matrix[0][2]=4; MDS->matrix[0][3]=3;
    MDS->matrix[0][4]=6; MDS->matrix[0][5]=2; MDS->matrix[0][6]=1; MDS->matrix[0][7]=1;
    for(i=1; i<v; ++i){
      for(j=0; j<v; ++j)
	MDS->matrix[i][j]=MDS->matrix[i-1][(j-1+v)%v];
    }
    break;
  default:
    printf("Size of state matrix must be 4, 6, or 8\n");
    exit(0);
  }
  //MDS set
  MDS_T=newState();
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j)
      MDS_T->matrix[i][j]=MDS->matrix[j][i];
  }
  //transpose of MDS set
}

void printState(cipherState *S){
  /* Pretty-prints the state S. */
  long i, j;

  for(i=0; i<v; ++i){
    printf("[ ");
    for(j=0; j<v; ++j)
      printf("%3ld ",S->matrix[i][j]);
    printf(" ]\n");
  }
  printf("\n");
}

cipherState *matrixMultiply(cipherState *A, cipherState *B){
  /* Returns the product A*B. */
  long i, j, k, sum;
  cipherState *ret;

  ret=newState();
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j){
      sum=0;
      for(k=0; k<v; ++k)
	sum+=A->matrix[i][k]*B->matrix[k][j];
      ret->matrix[i][j]=sum%Q;
    }
  }

  return ret;
}

void addRoundKey(cipherState *S, cipherState *K){
  /* Computes next round key and adds it to S */
  long i, j, coeff, count=0;

  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j){
      do{
	coeff=random()%OLDQ;
	count++;
      }while(gcd(coeff,OLDQ)>1);
      coeff=coeff%Q;
      S->matrix[i][j]=(S->matrix[i][j]+(coeff*K->matrix[i][j]))%Q;
    }
  }
}

void linearTransformation(cipherState *S){
  /* Applies mix columns and mix rows to S. */
  cipherState *tmp1, *tmp2;
  long i, j;
  
  tmp1=matrixMultiply(MDS,S);
  tmp2=matrixMultiply(tmp1,MDS_T);
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j)
      S->matrix[i][j]=tmp2->matrix[i][j];
  }
  deleteState(tmp1);
  deleteState(tmp2);
}

void Feistel(cipherState *S){
  /* Applies non-linear transformation (Feistel) to S. */
  cipherState *tmp;
  long i;
  
  tmp=newState();  
  for(i=1; i<v*v; ++i)
    tmp->matrix[i/v][i%v]=((S->matrix[(i-1)/v][(i-1)%v]*S->matrix[(i-1)/v][(i-1)%v])+S->matrix[i/v][i%v])%Q;
  for(i=1; i<v*v; ++i)
    S->matrix[i/v][i%v]=tmp->matrix[i/v][i%v];
  deleteState(tmp);
}

cipherState *rubatoBlock(cipherState *K, int r){
  /* Generates and returns (next) block of r-round Rubato key stream _without_ noise. */
  cipherState *S;
  long i;

  S=initialRubatoState();
  addRoundKey(S,K);
  for(i=0; i<r-1; ++i){
    linearTransformation(S);
    Feistel(S);
    addRoundKey(S,K);
  }
  linearTransformation(S);
  Feistel(S);
  linearTransformation(S);
  addRoundKey(S,K);

  return S;
}

