// deno-lint-ignore-file ban-types

const hex = (str: string) =>
  new Uint8Array(str.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
const msg = (str: string) => new TextEncoder().encode(str);

type GoldenVectorTestCase = {
  sk: Uint8Array;
  pk: Uint8Array;
  msg: Uint8Array;
  sig: {
    s: Uint8Array;
    R: Uint8Array;
  };
} & {};

export const GOLDEN_VECTORS: GoldenVectorTestCase[] = [
  {
    sk: hex(
      "d3038219539d7f542656e39cae386984b6c8fbfd94bbdae2137b368da886f2931f9aa921badc5b714d3d88c81aef701954311b83efb28e26",
    ),
    pk: hex(
      "ee93c4c8f2d58c57ec6f22e8624f4bcb132441638b3001d92f7c8be9a9e55c356e0834790c8348a233c2b3c6d09c8a11351491305c098059",
    ),
    msg: msg("Golden Vector Test"),
    sig: {
      s: hex(
        "4894eade4a5fec705d6bf9350a1b07915405b80c0b3de811bad6d819814e53736b95d1ccf897f366ca3493f71a5ca9dc75fc7f26b9460d34",
      ),
      R: hex(
        "2811c04c396574f3880587831f63ff65330eba583223f22d0a29cf057a0bd3d3a5273af2e5b0cc3342b39e24ed1a88bb708982e359a3431e",
      ),
    },
  },
  {
    sk: hex(
      "28c8c25ddaca004835640a0d76dffd2eb7e3b53758e7a323d849d81fbaf00dbb57ceced87557f06c126dc857f2eb66acd6188609c59bb608",
    ),
    pk: hex(
      "6082c782c08b46aa03043835788196f00b3569d642dad892e087ea453b833b5124e053f38efed0f8c330b8147de7e3891ee7ad2d61d03bee",
    ),
    msg: msg("Hello, world!"),
    sig: {
      s: hex(
        "3b11a2e417bae236e28e95fa5c68354475c1f030a81ae9a35030579c077b5cd27f750432c258173168a30b86fdf2ff768a7e82e45def502f",
      ),
      R: hex(
        "d45e9ac47e2d74b803e26080e0a656ddc8c253cd096c955b8cc089d9a333f191b39df11ccecb92a6aab1510b163c2d89627c7cad805089f7",
      ),
    },
  },
  {
    sk: hex(
      "cc736d766b718ec37547fc4743e5e84648dc993c839f76025aaec60bf7ceea3151c846270ffd923b655203f52ad9a53a1ea637bc97377628",
    ),
    pk: hex(
      "244a69894b6d6e8e6e14ddab25225824742deaf8dbf0ee2defd750f2722f7f9ef0b80d7e75d01242727999e015b22aae6148a43bd079390c",
    ),
    msg: msg(""),
    sig: {
      s: hex(
        "667331f829c01fc99c3e42488cd37d20b41858a54b64ebaf29bd0ca91c6b8b83887f0de11873bcb97d71cf02b6e63752920e9ea26ca65130",
      ),
      R: hex(
        "2eca632f118e3e278088c36c7c3e54700837df11e875a770e2f97725f694eced77bb5f42f27932a9c754f0be86b29e21a5709341e14fa99d",
      ),
    },
  },
  {
    sk: hex(
      "431ae2d0ea6fc99190069a037dc23b5e9708fd8ee7b3c4421684576e5d1b946c84fb72ff2b9ee7489d4306fcc2fca45c44213b5cc0d8da22",
    ),
    pk: hex(
      "de2f0f03d7902a93c59bc365b9c66f3926d55a5227b9ebac8ddff132da5495507b7d7149c87f13c6030d852526df1c5e1cc805ef3e2e7159",
    ),
    msg: msg("                              "),
    sig: {
      s: hex(
        "0bd699220e0a70f0d08235c9c3778229783bc79431b81681de80bbeb58612bee7c8cfe67bfdd5721444b315f6ed685381253c51414711f11",
      ),
      R: hex(
        "72d6e97df26fc8a68258d96ccdb33f4f64aabefb135952b9708cfe63502bd0f2b5934e137a45e588091d5d37e5e84c326ec4e2a7d976e2e4",
      ),
    },
  },
  {
    sk: hex(
      "bb01be9bbe4a8aa0f9d2cd2cb9d398d1d0dcfadf6d860b636ed97872359be6d28b90bfc34145b313af73bc0ad47796831569455848b02d2f",
    ),
    pk: hex(
      "326ab5ea0961657cda26f0f8c81f29b092cbdefa44d954c42632edc52f6bf1c236825feb4a232cbf3d60050ecadf100b26542f3f086b397a",
    ),
    msg: msg("The quick brown fox jumps over the lazy dog"),
    sig: {
      s: hex(
        "86e7f39ffea7b3eb79f443c6b7829dcd25b9813932c9ddb82ba4a31fd30e4a4429c579bc134ee3b924e8a9e26a39eadc0978da1cc63d332b",
      ),
      R: hex(
        "cc5fa8d00c0efe48db56feab38c79075178fd60dd984564d1d02ce4064d67375d3519481b05b392d19b35ec17435bc71ca4d80b4bef4b07c",
      ),
    },
  },
];
