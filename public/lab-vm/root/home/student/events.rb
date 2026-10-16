# vm-ruby-enumerable
#
# Uzupelnij dwie metody. Wynik wypisz do stdout w formacie:
#   suspicious=[1, 2, 9]
#   calm=[]
#   counts_by_severity={"low"=>3, "high"=>2}

E = [{'id' => 4, 'severity' => 'low',  'type' => 'file_open'},
     {'id' => 9, 'severity' => 'high', 'type' => 'exec'},
     {'id' => 2, 'severity' => 'high', 'type' => 'file_open'},
     {'id' => 7, 'severity' => 'low',  'type' => 'auth'},
     {'id' => 1, 'severity' => 'low',  'type' => 'exec'}]

CALM = [{'id' => 4, 'severity' => 'low', 'type' => 'file_open'},
        {'id' => 7, 'severity' => 'low', 'type' => 'auth'}]

def suspicious(events)
  # ...
end

def counts_by(events, key)
  # ...
end

puts "suspicious=#{suspicious(E).inspect}"
puts "calm=#{suspicious(CALM).inspect}"
puts "counts_by_severity=#{counts_by(E, 'severity').inspect}"
