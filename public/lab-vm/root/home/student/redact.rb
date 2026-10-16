# vm-ruby-redact
#
# redact(text) ma zwrocic [maskowany_tekst, liczba_zamaskowanych].
# Liczymy ZAMIANY, nie linie: karta moze wystapic dwa razy w jednej
# linii, a trzy razy w trzech.
def redact(text)
  # ...
end

puts redact('card 4111-1111-1111-1111 end').inspect
puts redact("4111 1111 1111 1111\n5555 5555 5555 5555").inspect
