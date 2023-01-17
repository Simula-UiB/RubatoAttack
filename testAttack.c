/**
 * \author  H{\aa}vard Raddum
 *
 * Program for testing attack on Rubato with weak q.
 * Modify code according to comments in code to test different variants.
 *
 **/

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "rubato.h"
#include "attack.h"

int main(int argc, char *argv[]){
  cipherState *K, *gK, *Km;
  long i, j, *KS, *GS, *canNoise, nr;
  double maxScore=0.0, sc;
  FILE *fp;

  /* Select parameters for Rubato */
  v=6;//size of linear transfomations in Rubato, (v x v) matrices
  nr=3;//number of rounds in Rubato
  sigma=1.6356633496458739795537788457;//standard deviation for Gaussian sampler, taken from
  //     https://github.com/KAIST-CryptLab/RtF-Transciphering/blob/master/ckks_fv/fv_rubato.go

  //OLDQ=Q=43976504;//26-bit number with 11 as factor
  //OLDQ=Q=25937124;//25-bit number with factor 2^2 * 3
  //OLDQ=Q=45890520;//26-bit number with 10 and 12 as factors
  OLDQ=Q=25937125;//25-bit number with factor 5
  K=newState();
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j)
      K->matrix[i][j]=random()%Q;
  }
  
  initMDSmatrices();
  initDGS();
  KS=realKeyStream(K,nr);//KS is Rubato key stream, modulo Q

  /* Select modulus for attack.  The new value of Q must be a factor of OLDQ */
  Q=5;  
  newModulus(KS);
  fixI1andI2();
 
  gK=newState();
  Km=newState();
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j){
      Km->matrix[i][j]=K->matrix[i][j]%Q;
    }
  }
  //Km is correct key, modulo small factor
  for(i=0; i<v; ++i){
    for(j=0; j<v; ++j)
      gK->matrix[i][j]=Km->matrix[i][j];
  }//fixing correct guess on non-guessed key elements
  
  fp=fopen("scoreValues.txt","w");//score values for all guessed keys will be written to this file
  canNoise=(long *)malloc(length*sizeof(long));

  /* Select how much to guess, and test the attack */
  for(i=0; i<15625; ++i){//adjust number of guessed keys according to fixGuess function below
    fixGuess128M(gK,i);//replace function according to Rubato variant (see bottom of attack.h)
    GS=guessKeyStream(gK,nr);
    for(j=0; j<length; ++j)
      canNoise[j]=(KS[j]-GS[j]+Q)%Q;     
   free(GS);
    
   sc=score(canNoise);
   fprintf(fp,"%1.4f\n",sc);
   if(sc>maxScore){
     printf("Score %1.3f for guessed K\n",sc);
     printState(gK);
     maxScore=sc;
   }
  }
  fclose(fp);
  
  printf("** Real Rubato secret key **\n");
  printState(K);//should match the last printed key modulo the small factor of OLDQ, when attack is successful
}
