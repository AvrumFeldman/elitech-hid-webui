# Elitech HID WebUI – Linux

Python alapú, helyben futó webes kezelőfelület Elitech USB/HID adatloggerek Linux alatti használatához.

A projekt jelenleg az újabb **Elitech RC-5** hardveren lett ténylegesen, végponttól végpontig tesztelve:

- USB VID:PID: `246c:9001`
- USB azonosítás: `FMSH MSC+HID`
- protokollverzió a tesztelt eszközön: `0x35`
- kommunikáció: közvetlen Linux `hidraw`

A cél nem egyetlen RC-5 változat köré épített egyszer használatos script, hanem egy olyan közös Linuxos kezelőfelület kialakítása, amely később további Elitech HID logger-modellekkel és más szenzortípusokkal is bővíthető.

> Ez egy nem hivatalos közösségi projekt. Nem áll kapcsolatban az Elitech Technology vállalattal, és az Elitech nem támogatja vagy hitelesíti.

---

## Miért készült?

A projekt egy egyszerű gyakorlati problémából indult: egy újabb Elitech RC-5 adatloggert Linux alatt is szerettem volna teljes értékűen használni anélkül, hogy a gyártó Windowsos alkalmazására lenne szükség.

A készülék USB-n látható volt Linux alatt, azonban az újabb `246c:9001` hardver csak részben bizonyult kompatibilisnek a korábban nyilvánosan visszafejtett Elitech protokollimplementációkkal. Az alapvető HID kommunikáció és több konfigurációs adat olvasása működött, de két fontos területen eltért a korábbi eszközöktől:

- a konfiguráció látszólag sikeresen elment, de fizikai újracsatlakoztatás után visszaállt a régi értékre;
- a mérési rekordok kiolvasásához az új firmware más munkamenet-kezelést igényelt.

A működés feltárásához:

- Linux alatt közvetlenül vizsgáltuk az USB/HID kommunikációt;
- felhasználtuk a nyilvános [`python-elitech`](https://github.com/pasccom/python-elitech) projekt korábbi protokollkutatásait;
- statikusan elemeztük az **ElitechLog Win V8.0.5.0** gyári alkalmazás működését;
- a visszafejtett folyamatokat valódi RC-5 hardveren, byte-szintű HID naplózással ellenőriztük;
- a konfiguráció mentését, a rekordok letöltését, a törléssel járó újrakonfigurálást és egy új mérési ciklus elindítását is valós eszközön teszteltük.

A cél tehát nem csak egy működő script létrehozása volt, hanem egy átlátható, reprodukálható Linuxos megoldás, amely később további Elitech modellek támogatásának alapja lehet.

---

## Mit tud jelenleg?

A WebUI három fő területre oszlik.

### Eszköz információk

- Elitech HID eszköz automatikus felismerése;
- modell- és sorozatszám kiolvasása;
- USB/HID eszközút megjelenítése;
- protokollverzió;
- memóriakapacitás és tárolt rekordszám;
- belső készülékidő;
- állapot- és konfigurációs mezők kiolvasása;
- USB/HID jogosultsági hiba felismerése és célzott `udev` szabály telepítése.

### Mérés konfigurálása

- mintavételi időköz beállítása;
- kézi indítási mód;
- készülékóra szinkronizálása a számítógép idejéhez;
- gombos leállítás engedélyezése/tiltása;
- szoftveres leállítás engedélyezése/tiltása;
- várható tárolási idő számítása a kapacitás és intervallum alapján;
- gyári ElitechLog-kompatibilis konfigurációs mentési folyamat az új RC-5 hardverhez.

A konfiguráció mentése **nem indítja el automatikusan a mérést**. A tesztelt RC-5 kézi indítási módot használ; mentés után a mérési ciklus a készülék ▶ gombjának hosszú megnyomásával indítható.

### Mérési eredmények

- mérési rekordok letöltése HID kapcsolaton keresztül;
- utolsó 100 / 500 / 2000 vagy az összes rekord beolvasása;
- időbélyeg és hőmérséklet dekódolása;
- rekordállapot és jelzőbitek megjelenítése;
- minimum, átlag és maximum hőmérséklet;
- adaptív időtengelyű hőmérséklet-grafikon;
- egérrel a legközelebbi valódi mérési pont kiemelése;
- pontos időpont, hőmérséklet és rekordsorszám megjelenítése a grafikonon;
- CSV export.

A táblázat és a CSV **páratartalom mezőt is megtart** a későbbi, páratartalom-képes Elitech modellekhez. A jelenleg tesztelt RC-5 csak hőmérsékletet mér, ezért ennél a modellnél a páratartalom értéke `—`.

---

## Támogatott eszközök

### Ténylegesen tesztelt

| Modell | VID:PID | Protokoll | Állapot |
|---|---|---:|---|
| Elitech RC-5, újabb MSC+HID hardver | `246c:9001` | `0x35` | Teljes alapfolyamat tesztelve |

A jelenlegi eszközfelderítés még konkrétan erre a VID:PID párosra van beállítva.

A program szerkezete több Elitech modell támogatása felé bővíthető, de más modellek kompatibilitása jelenleg **nem tekinthető igazoltnak**. A hosszabb távú terv modellfüggő eszközprofilok használata, így például egy hőmérséklet+páratartalom logger ugyanazon felületet használhatná saját szenzoradataival.

---

## Adatbiztonság és új mérési ciklus

A tesztelt RC-5 esetén a gyári konfigurációs mentési folyamat `FormatCommand` műveletet is használ. Ha a logger már tartalmaz mérési rekordokat, egy új konfiguráció mentése **törli a korábbi mérési adatokat**.

Ezért a program nem végez ilyen műveletet egyetlen véletlen kattintásra.

Ha a tárolt rekordok száma nagyobb mint nulla, a mentéshez két külön biztonsági jóváhagyás szükséges:

1. az első ablakban az `OK` gomb bal oldalon jelenik meg;
2. a második, végleges megerősítésnél az `OK` gomb jobb oldalon jelenik meg.

A cél az, hogy ne lehessen rutinból kétszer ugyanoda kattintva véletlenül törölni a méréseket.

A backend a jóváhagyott rekordszámot is ellenőrzi a művelet előtt. Ha a felület például 27 rekord törlését erősítette meg, de a készülék közben már más rekordszámot jelent, a mentés megszakad és új jóváhagyás szükséges.

Ajánlott sorrend egy mérési ciklus lezárásakor:

1. mérések beolvasása;
2. CSV export;
3. az exportált adatok ellenőrzése és mentése;
4. szükség esetén új konfiguráció mentése a két biztonsági jóváhagyással;
5. a készülék leválasztása;
6. új mérési ciklus kézi indítása a ▶ gomb hosszú megnyomásával.

A tesztelt RC-5 modellen ez a teljes folyamat működőképesen végig lett próbálva: meglévő rekordok kiolvasása után a program jóváhagyással újrakonfigurálta a készüléket, a rekordtár lenullázódott, a beállított 30 perces intervallum megmaradt, majd új mérési ciklus indult.

---

## Rendszerkövetelmények

A program Linux-specifikus, de nem Ubuntu-specifikus.

Szükséges:

- Linux;
- Python **3.10 vagy újabb**;
- Linux `hidraw` támogatás;
- `/sys/class/hidraw` és `/dev/hidraw*`;
- modern böngésző.

A program kizárólag a Python standard libraryt használja, ezért normál esetben nincs szükség `pip install` parancsra vagy `requirements.txt` fájlra.

Az automatikus USB-jogosultság telepítéséhez ezen felül szükséges:

- `udevadm`;
- `pkexec` / polkit;
- az `install` parancs.

### Linux disztribúciók

A fejlesztés és a hardvertesztek Ubuntu alatt történtek.

A program felépítése alapján várhatóan működik más hagyományos `udev` + `hidraw` környezetet használó disztribúciókon is, például:

- Debian;
- Linux Mint;
- Pop!_OS;
- Fedora;
- openSUSE;
- Arch Linux;
- Manjaro;
- Raspberry Pi OS.

NixOS, Alpine Linux, WSL vagy konténeres környezet esetén az USB/HID jogosultság és az eszközátadás külön konfigurációt igényelhet.

---

## Telepítés és indítás

Klónozd a repositoryt:

```bash
git clone https://github.com/andraschad/elitech-hid-webui-hun.git
cd elitech-hid-webui-hun
```

Indítsd el:

```bash
python3 elitech-webui.py
```

A program kiírja:

- az aktuális belső verziót;
- a ténylegesen futtatott script fájlnevét;
- a WebUI címét;
- a debug log helyét.

Példa:

```text
Elitech RC-5 Manager | v21-tab-session-recovery
---------------------------------------------
Web UI: http://127.0.0.1:8765/
Debug log: /home/user/elitech-hid-webui-hun/elitech-debug.log
Leállítás: Ctrl+C
```

A WebUI alapértelmezett címe:

```text
http://127.0.0.1:8765/
```

A szerver kizárólag a helyi loopback interfészen figyel, tehát alapértelmezésben nem érhető el a helyi hálózat más gépeiről.

Ha a böngésző nem nyílik meg automatikusan, a fenti címet kézzel is megnyithatod.

Leállítás:

```text
Ctrl+C
```

---

## USB/HID jogosultság

Linuxon a `/dev/hidraw*` eszközök használatához megfelelő jogosultság szükséges.

A WebUI képes automatikusan telepíteni egy célzott `udev` szabályt `pkexec` segítségével.

A jelenlegi szabály:

```udev
KERNEL=="hidraw*", ATTRS{idVendor}=="246c", ATTRS{idProduct}=="9001", MODE="0660", TAG+="uaccess"
```

A fájl helye:

```text
/etc/udev/rules.d/99-elitech-rc5.rules
```

Telepítés után szükség lehet a logger kihúzására és újbóli csatlakoztatására.

Nem ajánlott az egész WebUI-t `sudo` jogosultsággal futtatni. A célzott `udev` szabály biztonságosabb megoldás.

---

## Hogyan működik a mérési rekordok kiolvasása?

A mérések nem a készülék által publikált kis FAT/MSC meghajtóról kerülnek kiolvasásra, hanem a HID interfészen keresztül.

Az új `246c:9001` RC-5 rekordletöltése eltér a korábbi Elitech implementációktól. A program a gyári ElitechLogból visszafejtett kapcsolódási/read folyamatot reprodukálja, majd `GetRecord` kérésekkel tölti le a rekordokat.

A program a rekordletöltés előtt és után külön inicializálja a normál paraméterolvasási munkamenetet. Erre azért van szükség, mert ezen az új firmware-en a rekordletöltés után egyes rövid paraméterolvasások átmenetileg `0xFF` sentinel adatokat adhatnak vissza. A jelenlegi verzió ezt automatikusan kezeli, ezért a különböző WebUI tabok használati sorrendje nem befolyásolhatja a következő művelet eredményét.

---

## Grafikon

A hőmérséklet-idősor valódi időtengelyt használ.

Az X tengely felirata a mérés teljes időtartamához alkalmazkodik:

- rövid mérésnél óra és perc;
- több napnál dátum + idő;
- több hétnél vagy hónapnál nap/hónap jellegű felirat;
- hosszabb adatsornál hónap vagy év.

Ha az egeret a grafikon fölé mozgatod, a program az időben legközelebbi valódi mérési pontot választja ki, függőleges vonallal és ponttal jelöli, majd megmutatja:

- a pontos dátumot és időt;
- a hőmérsékletet;
- a mérési rekord sorszámát.

Nagy adatmennyiségnél a megjelenített vonal ritkítható a böngésző terhelésének csökkentésére, de az egérrel történő legközelebbi pont keresése továbbra is az eredeti mérési rekordok alapján történik.

---

## Debug logok

A program induláskor részletes debug naplót hoz létre az **aktuális munkakönyvtárban**:

```text
elitech-debug.log
```

A log rotálva van:

- egy logfájl legfeljebb kb. **2 MB**;
- legfeljebb **3 korábbi logfájl** kerül megőrzésre.

Tipikusan:

```text
elitech-debug.log
elitech-debug.log.1
elitech-debug.log.2
elitech-debug.log.3
```

A log többek között tartalmazza:

- az alkalmazás belső verzióját;
- a ténylegesen futtatott script fájlnevét;
- az eszköz felismerését;
- HID GET/SET kéréseket és válaszokat;
- nyers protokoll frame-eket hexadecimális formában;
- konfigurációs olvasást és írást;
- rekordletöltési műveleteket;
- nyers mérési rekordokat;
- a destruktív konfiguráció jóváhagyott rekordszámát;
- hibákat és Python tracebackeket.

A log első sora például:

```text
APPLICATION START | version=v21-tab-session-recovery | script=elitech-webui.py | ...
```

Ez szándékosan része a naplónak: hibakeresésnél azonnal látható, hogy ténylegesen melyik belső verzió és melyik fájl futott, így csökkenthető annak az esélye, hogy véletlenül egy korábbi scriptverzió eredményeit elemezzük.

### Adatvédelmi megjegyzés

A debug log tartalmazhat:

- eszköz-sorozatszámot;
- mérési időpontokat;
- hőmérsékleti adatokat;
- konfigurációs értékeket;
- teljes nyers HID frame-eket.

Ezért GitHub issue vagy más nyilvános helyre történő feltöltés előtt érdemes átnézni.

A repository `.gitignore` fájljában célszerű kizárni:

```gitignore
elitech-debug.log*
```

---

## Projektállapot

A projekt működő, de továbbra is aktívan fejlesztett állapotban van.

A jelenlegi, valós hardveren tesztelt fejlesztési állapot: **`v21-tab-session-recovery`**.

A `246c:9001` RC-5 esetén már működik:

- HID kommunikáció;
- eszközfelismerés;
- konfiguráció kiolvasása;
- tartós konfigurációs mentés;
- meglévő mérési rekordok biztonságos kiolvasása;
- rekorddekódolás;
- CSV export;
- adaptív, interaktív grafikon;
- rekordot tartalmazó logger újrakonfigurálása kettős biztonsági jóváhagyással;
- rekordtár törlése a gyári mentési folyamattal;
- új mérési ciklus előkészítése és kézi indítása;
- tabváltások és rekordletöltés utáni HID/paraméter-session automatikus helyreállítása.

A további logikus fejlesztési irányok:

- több Elitech VID:PID és modell támogatása;
- modellfüggő szenzorprofilok;
- hőmérséklet + páratartalom modellek tényleges hardvertesztje;
- további rekord- és állapotflag-ek dokumentálása;
- régebbi Elitech hardvergenerációk regressziós tesztelése.

---

## Technikai háttér

A kommunikáció Linuxon közvetlenül a `/dev/hidraw*` interfészen történik, külső HID Python könyvtár nélkül.

A projekt protokollkutatásának egy része a nyilvános:

[`pasccom/python-elitech`](https://github.com/pasccom/python-elitech)

projekt korábbi munkájára épül.

Az újabb `246c:9001` RC-5 viselkedéséhez szükséges további részeket a gyári **ElitechLog Win V8.0.5.0** statikus elemzésével és valódi hardveren végzett tesztekkel sikerült feltárni.

A gyári bináris nem része ennek a repositorynak.

---

## Licenc

A projekt GNU General Public License v3.0 alatt tehető közzé.

Lásd a repository `LICENSE` fájlját.

---

## Köszönet

Köszönet a [`python-elitech`](https://github.com/pasccom/python-elitech) projekt készítőinek a korábbi Elitech protokollkutatásért és a nyilvánosan elérhető implementációért.

A projekt célja, hogy ezt a munkát az újabb Elitech hardverek irányába továbbvigye, és egy használható, Linuxon natívan futó kezelőfelületet biztosítson hozzájuk.

---

## Figyelmeztetés

A program reverse engineering eredményeire épül, és nem hivatalos Elitech szoftver.

Mérési adatok törlésével járó konfigurációs művelet előtt mindig készíts exportot a fontos rekordokról. Kritikus, szabályozott vagy hitelesített mérési környezetben a program használata előtt külön validáció szükséges.
