#include "bignum.h"
#include <assert.h>
#include <string.h>

static char *fibonacci(int n) {
    bignum_t *f0 = bignum_from_uint(1);
    bignum_t *f1 = bignum_0();
    bignum_t *f2;

    for (int i = 2; i <= n; ++i) {
        f2 = f1;
        f1 = f0;
        f0 = bignum_add(NULL, f2, f1);
    }

    return bignum_to_dec(f0);
}

int main(int argc, char const *argv[]) {
    assert(strcmp(fibonacci(2), "1") == 0);
    assert(strcmp(fibonacci(10), "55") == 0);
    assert(strcmp(fibonacci(100), "354224848179261915075") == 0);
    assert(strcmp(fibonacci(1000),
                  "4346655768693745643568852767504062580256466051737178040248"
                  "1729089536555417949051890403879840079255169295922593080322"
                  "6347752096896232398733224711616429964409065331879382989696"
                  "49928516003704476137795166849228875") == 0);
    assert(
        strcmp(
            fibonacci(10000),
            "336447648764317832666216120051075433103021484606800639065647699746"
            "800814421666623681555955136337340255820653326808361593737347904838"
            "652682630408924630564318873545443695598274916066020998841839338646"
            "527313000888302692356736131351175792974378544137521305205043477016"
            "022647583189065278908551543661595829872796829875106312005754287834"
            "532155151038708182989697916131278562650331954871402142875326981879"
            "620469360978799003509623022910263681314931952756302278376284415403"
            "605844025721143349611800230912082870460889239623288354615057765832"
            "712525460935911282039252853934346209042452489294039017062338889910"
            "858410651831733604374707379085526317643257339937128719375877468974"
            "799263058370657428301616374089691784263786242128352581128205163702"
            "980893320999057079200643674262023897831114700540749984592503606335"
            "609338838319233867830561364353518921332797329081337326426526339897"
            "639227234078829281779535805709936910491754708089318410561463223382"
            "174656373212482263830921032977016480547262438423748624114530938122"
            "065649140327510866433945175121615265453613331113140424368548051067"
            "658434935238369596534280717687753283482343455573667197313927462736"
            "291082106792807847180353291311767789246590899386354593278945237776"
            "744061922403376386740040213303432974969020283281459334188268176838"
            "930720036347956231171031012919531697946076327375892535307725523759"
            "437884345040677155557790564504430166401194625809722167297586150269"
            "684431469520346149322911059706762432685159928347098912847067408620"
            "085871350162603120719031720860940812983215810772820763531866246112"
            "782455372085323653057759564300725177443150515396009051686032203491"
            "632226408852488524331580515348496224348482993809050704834824493274"
            "537326245677558790891871908036620580095947431500524025327097469953"
            "187707243768259074199396322659841474981936092852239450397071654431"
            "564213281576889080587831834049174345562705202235648464951961124602"
            "683139709750693826487066132645076650746115126775227486215986425307"
            "112984411826226610571635150692600298617049454250474913781151541399"
            "415506712562711971332527636319396069028956502882686083622410820505"
            "62430701794976171121233066073310059947366875") == 0);

    return 0;
}