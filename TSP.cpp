
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/time.h>

#define NO_OF_INDIVIDUAL 100

class Individual_sate
{
public:
    int gene[282];
    //280個の都市を回る順番を遺伝子とおく，最後に一巡して最初の都市に戻ってくるため，281この要素を持つ配列となる。
    //0番目の配列を無視したいから282個作って1～281まで作る
    double distance;
    //合計距離を適応度と置く
};

class city_state
{
public:
    double x;
    double y;
};

void init_city(city_state city[])
{
    city[1].x = 288;
    city[2].x = 288;
    city[3].x = 270;
    city[4].x = 256;
    city[5].x = 256;
    city[6].x = 246;
    city[7].x = 236;
    city[8].x = 228;
    city[9].x = 228;
    city[10].x = 220;
    city[11].x = 212;
    city[12].x = 204;
    city[13].x = 196;
    city[14].x = 188;
    city[15].x = 196;
    city[16].x = 188;
    city[17].x = 172;
    city[18].x = 164;
    city[19].x = 156;
    city[20].x = 148;
    city[21].x = 140;
    city[22].x = 148;
    city[23].x = 164;
    city[24].x = 172;
    city[25].x = 156;
    city[26].x = 140;
    city[27].x = 132;
    city[28].x = 124;
    city[29].x = 116;
    city[30].x = 104;
    city[31].x = 104;
    city[32].x = 104;
    city[33].x = 90;
    city[34].x = 80;
    city[35].x = 64;
    city[36].x = 64;
    city[37].x = 56;
    city[38].x = 56;
    city[39].x = 56;
    city[40].x = 56;
    city[41].x = 56;
    city[42].x = 56;
    city[43].x = 56;
    city[44].x = 40;
    city[45].x = 40;
    city[46].x = 40;
    city[47].x = 40;
    city[48].x = 40;
    city[49].x = 40;
    city[50].x = 40;
    city[51].x = 32;
    city[52].x = 32;
    city[53].x = 32;
    city[54].x = 32;
    city[55].x = 32;
    city[56].x = 32;
    city[57].x = 32;
    city[58].x = 32;
    city[59].x = 40;
    city[60].x = 56;
    city[61].x = 56;
    city[62].x = 48;
    city[63].x = 40;
    city[64].x = 32;
    city[65].x = 32;
    city[66].x = 24;
    city[67].x = 16;
    city[68].x = 16;
    city[69].x = 8;
    city[70].x = 8;
    city[71].x = 8;
    city[72].x = 8;
    city[73].x = 8;
    city[74].x = 8;
    city[75].x = 8;
    city[76].x = 16;
    city[77].x = 8;
    city[78].x = 8;
    city[79].x = 24;
    city[80].x = 32;
    city[81].x = 32;
    city[82].x = 32;
    city[83].x = 32;
    city[84].x = 32;
    city[85].x = 32;
    city[86].x = 40;
    city[87].x = 40;
    city[88].x = 40;
    city[89].x = 40;
    city[90].x = 44;
    city[91].x = 44;
    city[92].x = 44;
    city[93].x = 32;
    city[94].x = 24;
    city[95].x = 16;
    city[96].x = 16;
    city[97].x = 24;
    city[98].x = 32;
    city[99].x = 44;
    city[100].x = 56;
    city[101].x = 56;
    city[102].x = 56;
    city[103].x = 56;
    city[104].x = 56;
    city[105].x = 64;
    city[106].x = 72;
    city[107].x = 72;
    city[108].x = 56;
    city[109].x = 48;
    city[110].x = 56;
    city[111].x = 56;
    city[112].x = 48;
    city[113].x = 48;
    city[114].x = 56;
    city[115].x = 56;
    city[116].x = 48;
    city[117].x = 56;
    city[118].x = 56;
    city[119].x = 104;
    city[120].x = 104;
    city[121].x = 104;
    city[122].x = 104;
    city[123].x = 104;
    city[124].x = 104;
    city[125].x = 104;
    city[126].x = 116;
    city[127].x = 124;
    city[128].x = 132;
    city[129].x = 132;
    city[130].x = 140;
    city[131].x = 148;
    city[132].x = 156;
    city[133].x = 164;
    city[134].x = 172;
    city[135].x = 172;
    city[136].x = 172;
    city[137].x = 172;
    city[138].x = 172;
    city[139].x = 172;
    city[140].x = 180;
    city[141].x = 180;
    city[142].x = 180;
    city[143].x = 180;
    city[144].x = 180;
    city[145].x = 172;
    city[146].x = 172;
    city[147].x = 172;
    city[148].x = 172;
    city[149].x = 164;
    city[150].x = 148;
    city[151].x = 124;
    city[152].x = 124;
    city[153].x = 124;
    city[154].x = 124;
    city[155].x = 124;
    city[156].x = 124;
    city[157].x = 104;
    city[158].x = 104;
    city[159].x = 104;
    city[160].x = 104;
    city[161].x = 104;
    city[162].x = 104;
    city[163].x = 104;
    city[164].x = 104;
    city[165].x = 104;
    city[166].x = 92;
    city[167].x = 80;
    city[168].x = 72;
    city[169].x = 64;
    city[170].x = 72;
    city[171].x = 80;
    city[172].x = 80;
    city[173].x = 80;
    city[174].x = 88;
    city[175].x = 104;
    city[176].x = 124;
    city[177].x = 124;
    city[178].x = 132;
    city[179].x = 140;
    city[180].x = 132;
    city[181].x = 124;
    city[182].x = 124;
    city[183].x = 124;
    city[184].x = 124;
    city[185].x = 124;
    city[186].x = 132;
    city[187].x = 124;
    city[188].x = 120;
    city[189].x = 128;
    city[190].x = 136;
    city[191].x = 148;
    city[192].x = 162;
    city[193].x = 156;
    city[194].x = 172;
    city[195].x = 180;
    city[196].x = 180;
    city[197].x = 172;
    city[198].x = 172;
    city[199].x = 172;
    city[200].x = 180;
    city[201].x = 180;
    city[202].x = 188;
    city[203].x = 196;
    city[204].x = 204;
    city[205].x = 212;
    city[206].x = 220;
    city[207].x = 228;
    city[208].x = 228;
    city[209].x = 236;
    city[210].x = 236;
    city[211].x = 236;
    city[212].x = 228;
    city[213].x = 228;
    city[214].x = 236;
    city[215].x = 236;
    city[216].x = 228;
    city[217].x = 228;
    city[218].x = 236;
    city[219].x = 236;
    city[220].x = 228;
    city[221].x = 228;
    city[222].x = 236;
    city[223].x = 252;
    city[224].x = 260;
    city[225].x = 260;
    city[226].x = 260;
    city[227].x = 260;
    city[228].x = 260;
    city[229].x = 260;
    city[230].x = 260;
    city[231].x = 276;
    city[232].x = 276;
    city[233].x = 276;
    city[234].x = 276;
    city[235].x = 284;
    city[236].x = 284;
    city[237].x = 284;
    city[238].x = 284;
    city[239].x = 284;
    city[240].x = 284;
    city[241].x = 284;
    city[242].x = 288;
    city[243].x = 280;
    city[244].x = 276;
    city[245].x = 276;
    city[246].x = 276;
    city[247].x = 268;
    city[248].x = 260;
    city[249].x = 252;
    city[250].x = 260;
    city[251].x = 260;
    city[252].x = 236;
    city[253].x = 228;
    city[254].x = 228;
    city[255].x = 236;
    city[256].x = 236;
    city[257].x = 228;
    city[258].x = 228;
    city[259].x = 228;
    city[260].x = 228;
    city[261].x = 220;
    city[262].x = 212;
    city[263].x = 204;
    city[264].x = 196;
    city[265].x = 188;
    city[266].x = 180;
    city[267].x = 180;
    city[268].x = 180;
    city[269].x = 180;
    city[270].x = 180;
    city[271].x = 196;
    city[272].x = 204;
    city[273].x = 212;
    city[274].x = 220;
    city[275].x = 228;
    city[276].x = 236;
    city[277].x = 246;
    city[278].x = 252;
    city[279].x = 260;
    city[280].x = 280;
    city[1].y = 149;
    city[2].y = 129;
    city[3].y = 133;
    city[4].y = 141;
    city[5].y = 157;
    city[6].y = 157;
    city[7].y = 169;
    city[8].y = 169;
    city[9].y = 161;
    city[10].y = 169;
    city[11].y = 169;
    city[12].y = 169;
    city[13].y = 169;
    city[14].y = 169;
    city[15].y = 161;
    city[16].y = 145;
    city[17].y = 145;
    city[18].y = 145;
    city[19].y = 145;
    city[20].y = 145;
    city[21].y = 145;
    city[22].y = 169;
    city[23].y = 169;
    city[24].y = 169;
    city[25].y = 169;
    city[26].y = 169;
    city[27].y = 169;
    city[28].y = 169;
    city[29].y = 161;
    city[30].y = 153;
    city[31].y = 161;
    city[32].y = 169;
    city[33].y = 165;
    city[34].y = 157;
    city[35].y = 157;
    city[36].y = 165;
    city[37].y = 169;
    city[38].y = 161;
    city[39].y = 153;
    city[40].y = 145;
    city[41].y = 137;
    city[42].y = 129;
    city[43].y = 121;
    city[44].y = 121;
    city[45].y = 129;
    city[46].y = 137;
    city[47].y = 145;
    city[48].y = 153;
    city[49].y = 161;
    city[50].y = 169;
    city[51].y = 169;
    city[52].y = 161;
    city[53].y = 153;
    city[54].y = 145;
    city[55].y = 137;
    city[56].y = 129;
    city[57].y = 121;
    city[58].y = 113;
    city[59].y = 113;
    city[60].y = 113;
    city[61].y = 105;
    city[62].y = 99;
    city[63].y = 99;
    city[64].y = 97;
    city[65].y = 89;
    city[66].y = 89;
    city[67].y = 97;
    city[68].y = 109;
    city[69].y = 109;
    city[70].y = 97;
    city[71].y = 89;
    city[72].y = 81;
    city[73].y = 73;
    city[74].y = 65;
    city[75].y = 57;
    city[76].y = 57;
    city[77].y = 49;
    city[78].y = 41;
    city[79].y = 45;
    city[80].y = 41;
    city[81].y = 49;
    city[82].y = 57;
    city[83].y = 65;
    city[84].y = 73;
    city[85].y = 81;
    city[86].y = 83;
    city[87].y = 73;
    city[88].y = 63;
    city[89].y = 51;
    city[90].y = 43;
    city[91].y = 35;
    city[92].y = 27;
    city[93].y = 25;
    city[94].y = 25;
    city[95].y = 25;
    city[96].y = 17;
    city[97].y = 17;
    city[98].y = 17;
    city[99].y = 11;
    city[100].y = 9;
    city[101].y = 17;
    city[102].y = 25;
    city[103].y = 33;
    city[104].y = 41;
    city[105].y = 41;
    city[106].y = 41;
    city[107].y = 49;
    city[108].y = 49;
    city[109].y = 51;
    city[110].y = 57;
    city[111].y = 65;
    city[112].y = 63;
    city[113].y = 73;
    city[114].y = 73;
    city[115].y = 81;
    city[116].y = 83;
    city[117].y = 89;
    city[118].y = 97;
    city[119].y = 97;
    city[120].y = 105;
    city[121].y = 113;
    city[122].y = 121;
    city[123].y = 129;
    city[124].y = 137;
    city[125].y = 145;
    city[126].y = 145;
    city[127].y = 145;
    city[128].y = 145;
    city[129].y = 137;
    city[130].y = 137;
    city[131].y = 137;
    city[132].y = 137;
    city[133].y = 137;
    city[134].y = 125;
    city[135].y = 117;
    city[136].y = 109;
    city[137].y = 101;
    city[138].y = 93;
    city[139].y = 85;
    city[140].y = 85;
    city[141].y = 77;
    city[142].y = 69;
    city[143].y = 61;
    city[144].y = 53;
    city[145].y = 53;
    city[146].y = 61;
    city[147].y = 69;
    city[148].y = 77;
    city[149].y = 81;
    city[150].y = 85;
    city[151].y = 85;
    city[152].y = 93;
    city[153].y = 109;
    city[154].y = 125;
    city[155].y = 117;
    city[156].y = 101;
    city[157].y = 89;
    city[158].y = 81;
    city[159].y = 73;
    city[160].y = 65;
    city[161].y = 49;
    city[162].y = 41;
    city[163].y = 33;
    city[164].y = 25;
    city[165].y = 17;
    city[166].y = 9;
    city[167].y = 9;
    city[168].y = 9;
    city[169].y = 21;
    city[170].y = 25;
    city[171].y = 25;
    city[172].y = 25;
    city[173].y = 41;
    city[174].y = 49;
    city[175].y = 57;
    city[176].y = 69;
    city[177].y = 77;
    city[178].y = 81;
    city[179].y = 65;
    city[180].y = 61;
    city[181].y = 61;
    city[182].y = 53;
    city[183].y = 45;
    city[184].y = 37;
    city[185].y = 29;
    city[186].y = 21;
    city[187].y = 21;
    city[188].y = 9;
    city[189].y = 9;
    city[190].y = 9;
    city[191].y = 9;
    city[192].y = 9;
    city[193].y = 25;
    city[194].y = 21;
    city[195].y = 21;
    city[196].y = 29;
    city[197].y = 29;
    city[198].y = 37;
    city[199].y = 45;
    city[200].y = 45;
    city[201].y = 37;
    city[202].y = 41;
    city[203].y = 49;
    city[204].y = 57;
    city[205].y = 65;
    city[206].y = 73;
    city[207].y = 69;
    city[208].y = 77;
    city[209].y = 77;
    city[210].y = 69;
    city[211].y = 61;
    city[212].y = 61;
    city[213].y = 53;
    city[214].y = 53;
    city[215].y = 45;
    city[216].y = 45;
    city[217].y = 37;
    city[218].y = 37;
    city[219].y = 29;
    city[220].y = 29;
    city[221].y = 21;
    city[222].y = 21;
    city[223].y = 21;
    city[224].y = 29;
    city[225].y = 37;
    city[226].y = 45;
    city[227].y = 53;
    city[228].y = 61;
    city[229].y = 69;
    city[230].y = 77;
    city[231].y = 77;
    city[232].y = 69;
    city[233].y = 61;
    city[234].y = 53;
    city[235].y = 53;
    city[236].y = 61;
    city[237].y = 69;
    city[238].y = 77;
    city[239].y = 85;
    city[240].y = 93;
    city[241].y = 101;
    city[242].y = 109;
    city[243].y = 109;
    city[244].y = 101;
    city[245].y = 93;
    city[246].y = 85;
    city[247].y = 97;
    city[248].y = 109;
    city[249].y = 101;
    city[250].y = 93;
    city[251].y = 85;
    city[252].y = 85;
    city[253].y = 85;
    city[254].y = 93;
    city[255].y = 93;
    city[256].y = 101;
    city[257].y = 101;
    city[258].y = 109;
    city[259].y = 117;
    city[260].y = 125;
    city[261].y = 125;
    city[262].y = 117;
    city[263].y = 109;
    city[264].y = 101;
    city[265].y = 93;
    city[266].y = 93;
    city[267].y = 101;
    city[268].y = 109;
    city[269].y = 117;
    city[270].y = 125;
    city[271].y = 145;
    city[272].y = 145;
    city[273].y = 145;
    city[274].y = 145;
    city[275].y = 145;
    city[276].y = 145;
    city[277].y = 141;
    city[278].y = 125;
    city[279].y = 129;
    city[280].y = 133;
}

void shuffle(int array[], int size)
{
    for (int i = 0; i < size; i++)
    {
        int j = rand() % size;
        int t = array[i];
        array[i] = array[j];
        array[j] = t;
    }
}

void init_gene(Individual_sate Individual[])
{
    int i, j;
    int typeset[279] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280};

    for (i = 1; i <= NO_OF_INDIVIDUAL; i++)
    {
        //全て遺伝子は一番目の都市を最初に回る。
        Individual[i].gene[1] = 1;
        //全ての遺伝子は最後に一番目の都市に戻る。
        Individual[i].gene[281] = 1;
    }

    for (i = 1; i <= NO_OF_INDIVIDUAL; i++)
    {
        //typesetをシャッフル
        srand(time(NULL));
        shuffle(typeset, 279);
        for (j = 2; j <= 280; j++)
        {
            //シャッフルしたタイプセットの値をコピー
            Individual[i].gene[j] = typeset[j];
        }
    }
}

void calc_distance(Individual_sate individual[], int size, city_state city[])
{
    int i = 1;
    int j = 1;

    for (j = 1; j <= NO_OF_INDIVIDUAL; j++)
    {
        for (i = 1; i < size; i++)
        {
            individual[j].distance =
                sqrt(abs(pow(city[individual[j].gene[i+1]].x - city[individual[j].gene[i]].x, 2) - pow(city[individual[j].gene[i+1]].y - city[individual[j].gene[i]].y, 2))) + individual[j].distance;
        }
    }
    
}

int main()
{
    printf("checkpoint\n");
    int i;
    city_state city[281];
    Individual_sate Individual[NO_OF_INDIVIDUAL];
    Individual_sate Individual_next[NO_OF_INDIVIDUAL+1];
    init_city(city);
    printf("checkpoint\n");

    init_gene(Individual);
    
    calc_distance(Individual, 281, city);


    printf("checkpoint\n");

    printf("indubial[1].distance = %f\n", Individual[1].distance);
    printf("indubial[100].distance = %f\n", Individual[NO_OF_INDIVIDUAL].distance);

    printf("%d", city[1].x);
    return 0;
}
