#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int arg, char **argv)
{
      int fd, ret;
      struct sockaddr_in addr;
      char str[] = "Test1234";


      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); //localhost
      addr.sin_port = htons(7001); //fest in server

      fd = socket(AF_INET, SOCK_STREAM, 0);

      if ( fd <= 0 ){
            printf("Error socket(): %i\n", fd);
            exit(1);
      }

      ret = connect(fd, (struct sockaddr *) &addr, sizeof(addr));

      if(ret < 0){
            printf("Error connect(): %i\n", ret);
            return -1;
      }

      ret = write(fd, str, sizeof(str));

      if(ret != sizeof(str)){
            printf("Error write: %i", ret);
            exit(1);
      }

      close(fd);

      return 0;
}