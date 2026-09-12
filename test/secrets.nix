# Test rules file for wagenix integration tests.
#
# Recipients:
#   testKey   - test/id_ed25519 (automated tests, always use -i test/id_ed25519)
#   localKey  - Windows machine key
#               (C:\Users\lorlike\.ssh\id_ed25519)
#               enables manual testing WITHOUT -i on Windows
#   wslKey    - WSL machine key
#               (~/.ssh/id_ed25519, lorlike@nixos)
#               enables manual testing WITHOUT -i on WSL
let
  # Test-only key; the private key is checked in at test/id_ed25519.
  testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICquxtBQ0TGWj1MQe0c7X7Ry8xVldH8G2S5/eaaHQgcQ wagenix-test-key";

  # Local machine key (Windows: C:\Users\lorlike\.ssh\id_ed25519).
  # Lets you run manual tests on Windows without specifying -i.
  localKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAoyDyrTwS+/Sa4lR5SIbs7Pojq3L/YlFAPvgjhLXR0K lorlike@DESKTOP-BMVK2JC";

  # WSL machine key (~/.ssh/id_ed25519).
  # Lets you run manual tests on WSL without specifying -i.
  wslKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFLZLrFnSYLl2dqObi9P38WW6NtTJfZPuE6SBYWwBU80 lorlike@nixos";
in
{
  "secret1.age".publicKeys = [
    testKey
    localKey
    wslKey
  ];
  "armored-secret.age" = {
    publicKeys = [
      testKey
      localKey
      wslKey
    ];
    armor = true;
  };
}
