#include "obscuraproto/stream.hpp"

namespace ObscuraProto {

    void Stream::write(const byte_vector& data) {
        PayloadBuilder builder(OpCode::STREAM_DATA);
        builder.add_param(stream_id_);
        builder.add_param(data);
        send_fn_(builder.build());
    }

    void Stream::end() {
        PayloadBuilder builder(OpCode::STREAM_END);
        builder.add_param(stream_id_);
        send_fn_(builder.build());
    }

    void Stream::cancel() {
        PayloadBuilder builder(OpCode::STREAM_CANCEL);
        builder.add_param(stream_id_);
        send_fn_(builder.build());
    }

}  // namespace ObscuraProto
