#include "bignum.h"
#include <assert.h>
#include <string.h>

static char *factorial(int n) {
    bignum_t *f = bignum_from_uint(1);

    for (int i = 2; i <= n; ++i) {
        bignum_t *m = bignum_from_uint(i);
        f = bignum_mul(f, f, m);
    }

    return bignum_to_dec(f);
}

int main(int argc, char const *argv[]) {
    assert(strcmp(factorial(2), "2") == 0);
    assert(strcmp(factorial(10), "3628800") == 0);
    assert(strcmp(factorial(100), "93326215443944152681699238856266700490715968"
                                  "26438162146859296389521759999322991560894146"
                                  "39761565182862536979208272237582511852109168"
                                  "64000000000000000000000000") == 0);
    assert(
        strcmp(factorial(1000),
               "402387260077093773543702433923003985719374864210714632543799910"
               "429938512398629020592044208486969404800479988610197196058631666"
               "872994808558901323829669944590997424504087073759918823627727188"
               "732519779505950995276120874975462497043601418278094646496291056"
               "393887437886487337119181045825783647849977012476632889835955735"
               "432513185323958463075557409114262417474349347553428646576611667"
               "797396668820291207379143853719588249808126867838374559731746136"
               "085379534524221586593201928090878297308431392844403281231558611"
               "036976801357304216168747609675871348312025478589320767169132448"
               "426236131412508780208000261683151027341827977704784635868170164"
               "365024153691398281264810213092761244896359928705114964975419909"
               "342221566832572080821333186116811553615836546984046708975602900"
               "950537616475847728421889679646244945160765353408198901385442487"
               "984959953319101723355556602139450399736280750137837615307127761"
               "926849034352625200015888535147331611702103968175921510907788019"
               "393178114194545257223865541461062892187960223838971476088506276"
               "862967146674697562911234082439208160153780889893964518263243671"
               "616762179168909779911903754031274622289988005195444414282012187"
               "361745992642956581746628302955570299024324153181617210465832036"
               "786906117260158783520751516284225540265170483304226143974286933"
               "061690897968482590125458327168226458066526769958652682272807075"
               "781391858178889652208164348344825993266043367660176999612831860"
               "788386150279465955131156552036093988180612138558600301435694527"
               "224206344631797460594682573103790084024432438465657245014402821"
               "885252470935190620929023136493273497565513958720559654228749774"
               "011413346962715422845862377387538230483865688976461927383814900"
               "140767310446640259899490222221765904339901886018566526485061799"
               "702356193897017860040811889729918311021171229845901641921068884"
               "387121855646124960798722908519296819372388642614839657382291123"
               "125024186649353143970137428531926649875337218940694281434118520"
               "158014123344828015051399694290153483077644569099073152433278288"
               "269864602789864321139083506217095002597389863554277196742822248"
               "757586765752344220207573630569498825087968928162753848863396909"
               "959826280956121450994871701244516461260379029309120889086942028"
               "510640182154399457156805941872748998094254742173582401063677404"
               "595741785160829230135358081840096996372524230560855903700624271"
               "243416909004153690105933983835777939410970027753472000000000000"
               "000000000000000000000000000000000000000000000000000000000000000"
               "000000000000000000000000000000000000000000000000000000000000000"
               "000000000000000000000000000000000000000000000000000000000000000"
               "000000000000000000000000000000000000000000000000") == 0);

    return 0;
}
